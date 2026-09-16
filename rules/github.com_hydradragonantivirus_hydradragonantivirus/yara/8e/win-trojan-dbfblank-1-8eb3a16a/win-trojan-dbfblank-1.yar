rule Win_Trojan_DBFBlank_1
{
strings:
	$a0 = { 33c08ed8813e8801564f1f75212e813c }


condition:
	$a0
}