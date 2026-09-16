rule Win_Trojan_Shanghai_II_1
{
strings:
	$a0 = { 041d000510002e010609012e01060b012ea10b018ed02e8b260d012eff2e07018cc53c457409 }


condition:
	$a0
}