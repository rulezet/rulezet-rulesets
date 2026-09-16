rule Win_Trojan_Eliza_4
{
strings:
	$a0 = { 2180fe327612813e5c058000720ac606600501c6065e05 }


condition:
	$a0
}