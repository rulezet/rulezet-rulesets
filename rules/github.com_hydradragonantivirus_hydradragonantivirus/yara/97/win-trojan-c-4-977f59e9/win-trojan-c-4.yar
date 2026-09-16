rule Win_Trojan_C_4
{
strings:
	$a0 = { 0f8db74d01bc830631343124464c75f8 }


condition:
	$a0
}