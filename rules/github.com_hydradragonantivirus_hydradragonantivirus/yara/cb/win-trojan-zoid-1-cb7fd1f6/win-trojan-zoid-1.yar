rule Win_Trojan_Zoid_1
{
strings:
	$a0 = { cd213c037303eb1890b8ccffcd213dffcc740d2e8c0e4c062eff1e4a06eb409058fa8ccb2e2b1ed4068bd32e03 }


condition:
	$a0
}