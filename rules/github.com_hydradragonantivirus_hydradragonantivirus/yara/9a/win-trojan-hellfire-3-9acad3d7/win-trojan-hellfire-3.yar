rule Win_Trojan_Hellfire_3
{
strings:
	$a0 = { 21e80300e91efcbe030189f7b90f02ad350000abe2f9c3 }


condition:
	$a0
}