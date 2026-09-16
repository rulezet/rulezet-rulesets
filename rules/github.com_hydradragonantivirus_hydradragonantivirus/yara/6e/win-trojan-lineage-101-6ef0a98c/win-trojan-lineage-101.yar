rule Win_Trojan_Lineage_101
{
strings:
	$a0 = { 62621665e471387f679b059d1e8e4cb44e1ccc7eb624edebca804a1a30626c6a2bb9f4a929c71bebda20fce4a9c2c618e89f7a1b1a9664890ee144e82d8dad33de470804 }


condition:
	$a0
}