rule Win_Trojan_PRSC1024_1
{
strings:
	$a0 = { b800001e8ed8a172041f3df0f07505a1 }


condition:
	$a0
}