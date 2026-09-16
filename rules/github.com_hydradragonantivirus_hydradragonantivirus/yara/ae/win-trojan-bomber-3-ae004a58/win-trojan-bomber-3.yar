rule Win_Trojan_Bomber_3
{
strings:
	$a0 = { 0a54686520656e642e2e2e9affff00 }


condition:
	$a0
}