rule Win_Trojan_ColDir_1
{
strings:
	$a0 = { bab901cd218bc8bab9018b1e1402b440cd2159803e160201741083c63ec606160201e2c3eb }


condition:
	$a0
}