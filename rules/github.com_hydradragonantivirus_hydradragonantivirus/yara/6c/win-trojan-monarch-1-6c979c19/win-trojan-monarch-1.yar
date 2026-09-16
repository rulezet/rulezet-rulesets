rule Win_Trojan_Monarch_1
{
strings:
	$a0 = { 0101eb016981efe003eb01462e8b850501eb01d2b9d7038db507012e3104eb012546eb01 }


condition:
	$a0
}