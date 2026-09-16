rule Win_Trojan_Zorm_3
{
strings:
	$a0 = { d2b91100b43dcd210414bb24002e300743e2fa9038d0103516d5ad2316a6 }


condition:
	$a0
}