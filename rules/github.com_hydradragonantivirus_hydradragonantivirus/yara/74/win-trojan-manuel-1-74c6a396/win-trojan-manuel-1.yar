rule Win_Trojan_Manuel_1
{
strings:
	$a0 = { c3a675fbf8c3fc268a25ac3c0074153ac475f7574756e8 }


condition:
	$a0
}