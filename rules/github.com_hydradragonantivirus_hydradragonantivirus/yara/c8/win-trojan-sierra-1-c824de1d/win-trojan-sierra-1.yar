rule Win_Trojan_Sierra_1
{
strings:
	$a0 = { ab0050d1e8fecc7403e96c015351520656571e5589e50aed755bd0e07227e82d01e815017255e8bc00741ae82001 }


condition:
	$a0
}