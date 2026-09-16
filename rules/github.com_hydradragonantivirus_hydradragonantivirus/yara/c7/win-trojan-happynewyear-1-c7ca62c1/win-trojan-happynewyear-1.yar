rule Win_Trojan_HappyNewYear_1
{
strings:
	$a0 = { ac028c0e86009d8edfac0ac075fb }


condition:
	$a0
}