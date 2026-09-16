rule Win_Trojan_QFat_6
{
strings:
	$a0 = { 6a326a029a845a000083c40cff76feff76fc666a006a326a039a845a000083c40c1e688a00 }


condition:
	$a0
}