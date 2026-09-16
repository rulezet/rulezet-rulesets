rule Win_Trojan_Gen_54
{
strings:
	$a0 = { 8db74b01bc880631343124464c75f8 }


condition:
	$a0
}