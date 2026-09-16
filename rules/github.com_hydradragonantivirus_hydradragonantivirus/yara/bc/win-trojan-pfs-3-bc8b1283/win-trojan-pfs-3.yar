rule Win_Trojan_PFS_3
{
strings:
	$a0 = { 07b402b008ba8000b90300cd1306b88f0150cb }


condition:
	$a0
}