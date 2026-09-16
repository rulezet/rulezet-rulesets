rule Win_Trojan_C_319
{
strings:
	$a0 = { 6400610074006500[0-16]6e006f006f006d006d002e006f006400740022 }


condition:
	$a0
}