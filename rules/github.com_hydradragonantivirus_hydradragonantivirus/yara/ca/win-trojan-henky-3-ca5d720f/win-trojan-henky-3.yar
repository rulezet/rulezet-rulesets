rule Win_Trojan_Henky_3
{
strings:
	$a0 = { 52ff95ee224100c348656e4b7920656e20504c454e4f2045464543544f8d95592141 }


condition:
	$a0
}