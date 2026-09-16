rule Win_Trojan_LiquidPower_1
{
strings:
	$a0 = { 9e1d01b9c7012e8b86fa042e31074343e2f958595bc353 }


condition:
	$a0
}