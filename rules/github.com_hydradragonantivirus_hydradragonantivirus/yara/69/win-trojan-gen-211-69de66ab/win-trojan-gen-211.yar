rule Win_Trojan_Gen_211
{
strings:
	$a0 = { 30fd3cc2333269500653cb40ccb05fc0014bf7b7014587eff00d256fe919f0f2f0a1b0e13f }


condition:
	$a0
}