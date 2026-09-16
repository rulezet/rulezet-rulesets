rule Win_Trojan_Etr_1
{
strings:
	$a0 = { 12b9c403bf10002e8135000047e2f80e17bd00008edbc53684002e89b6a8032e8c9eaa030e1f068d96ec00b8014333 }


condition:
	$a0
}