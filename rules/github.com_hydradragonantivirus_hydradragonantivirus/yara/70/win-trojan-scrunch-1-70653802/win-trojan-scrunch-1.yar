rule Win_Trojan_Scrunch_1
{
strings:
	$a0 = { a4c686160306b41a8d96eb02cd21b447b2008db6ab02cd }


condition:
	$a0
}