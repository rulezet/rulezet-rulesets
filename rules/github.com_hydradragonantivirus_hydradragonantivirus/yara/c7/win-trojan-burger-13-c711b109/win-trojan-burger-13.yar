rule Win_Trojan_Burger_13
{
strings:
	$a0 = { 2ec7064b020000b419cd212ea27b02b447b2008d367d02cd21f87320b4178d165502cd213cff7514b42ccd212ea07b028bdab90200b600cd26e9fa00b43b }


condition:
	$a0
}