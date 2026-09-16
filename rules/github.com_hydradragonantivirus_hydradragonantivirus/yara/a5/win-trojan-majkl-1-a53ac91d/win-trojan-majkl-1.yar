rule Win_Trojan_Majkl_1
{
strings:
	$a0 = { 1304049026a11304bb4000f7e32d10008ec0bb0001b402b00390ba8000b90400cd1306b8fd }


condition:
	$a0
}