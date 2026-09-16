rule Win_Trojan_DarthVader_7
{
strings:
	$a0 = { 8b75f23c9f75eead938bb78000bf7e01 }


condition:
	$a0
}