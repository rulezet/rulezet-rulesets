rule Win_Trojan_Tower_2
{
strings:
	$a0 = { 1800ba0c01b409cd21b8004ccd21284329203139393320416d655d1e062bc08ec08ed8bf4002397d2574198d76fdb9 }


condition:
	$a0
}