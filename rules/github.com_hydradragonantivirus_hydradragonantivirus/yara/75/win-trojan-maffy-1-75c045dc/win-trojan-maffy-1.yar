rule Win_Trojan_Maffy_1
{
strings:
	$a0 = { b80042cd21b43fb903008bd5cd21727581be2400e8fd }


condition:
	$a0
}