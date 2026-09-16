rule Win_Trojan_Burger_8
{
strings:
	$a0 = { 470401508ad08d364602cd2158b40e }


condition:
	$a0
}