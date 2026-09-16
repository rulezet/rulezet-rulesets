rule Win_Trojan_Axe_4
{
strings:
	$a0 = { fa2e8c1642012e892640018ccc8ed4bc5b00fb601e062e8a260a000e07bb5d00b9810026302743d0cce2f8b806fecd }


condition:
	$a0
}