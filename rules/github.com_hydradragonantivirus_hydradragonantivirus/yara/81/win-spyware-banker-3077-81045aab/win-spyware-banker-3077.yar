rule Win_Spyware_Banker_3077
{
strings:
	$a0 = { 22277c264d2e2c48d450aa78eb80dce558bc733d8670c125a195044e78dce8586e0261e74498843df0614ac47b37039f9e49 }


condition:
	$a0
}