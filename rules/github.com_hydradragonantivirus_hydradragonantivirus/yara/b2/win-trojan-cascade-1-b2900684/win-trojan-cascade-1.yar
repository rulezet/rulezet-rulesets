rule Win_Trojan_Cascade_1
{
strings:
	$a0 = { fa8bece800005b81eb????[1-8]8db7????bc????31343124464c75f8 }


condition:
	$a0
}