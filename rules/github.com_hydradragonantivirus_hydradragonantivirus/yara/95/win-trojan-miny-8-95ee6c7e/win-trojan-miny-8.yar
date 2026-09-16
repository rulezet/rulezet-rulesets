rule Win_Trojan_Miny_8
{
strings:
	$a0 = { 02c6068d023db000e8c70033d2b98b02b440cd218b169002b000e8b500b040ba8a02b90400e8 }


condition:
	$a0
}