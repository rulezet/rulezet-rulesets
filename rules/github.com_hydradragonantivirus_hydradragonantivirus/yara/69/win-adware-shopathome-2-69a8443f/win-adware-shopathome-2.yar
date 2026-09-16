rule Win_Adware_ShopAtHome_2
{
strings:
	$a0 = { 53656c65637452656261746573446f776e6c6f616457696e646f77 }


condition:
	$a0
}