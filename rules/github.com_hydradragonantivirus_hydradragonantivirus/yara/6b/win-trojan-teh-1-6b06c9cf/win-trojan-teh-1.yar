rule Win_Trojan_TEH_1
{
strings:
	$a0 = { 2e8b1e6503b98702ba0001cd21c32ea1810333d2bb1000f7f3402ea37903c30e1f2eff368303 }


condition:
	$a0
}