rule Win_Trojan_P800_1
{
strings:
	$a0 = { e90000fa95e800005e83c619fc8bfe33d2b981 }


condition:
	$a0
}