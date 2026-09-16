rule Win_Trojan_Ficknitz_1
{
strings:
	$a0 = { 1e1e18d1e38b46048987a61bff061e1833c05dc3558bec1eb4408b5e048b4e0ac55606cd21 }


condition:
	$a0
}