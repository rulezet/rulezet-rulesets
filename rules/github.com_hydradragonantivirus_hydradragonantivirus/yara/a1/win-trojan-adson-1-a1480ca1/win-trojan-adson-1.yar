rule Win_Trojan_Adson_1
{
strings:
	$a0 = { 8db5372040008bfeb9bc000000bb00000000ad92ad3bd377125352f7e35b03c383d2005bab92abe2e9eb05ab92abe2e2 }


condition:
	$a0
}