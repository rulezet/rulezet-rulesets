rule Win_Trojan_Trooper_1
{
strings:
	$a0 = { 8800fc2e8c9f52000e1f2e80bf51000174208db70400bf0001b91c00f3a48c8f1a00c787180000018c97120089 }


condition:
	$a0
}