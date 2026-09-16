rule Win_Trojan_ArmyBoots_1
{
strings:
	$a0 = { cd2181f90df074558cd8488ed833ff8ec7803d5a75 }


condition:
	$a0
}