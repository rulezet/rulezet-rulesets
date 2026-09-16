rule Win_Trojan_Grog_14
{
strings:
	$a0 = { 023d90cd21909390b43f9006901f90baef0190b9ffff90 }


condition:
	$a0
}