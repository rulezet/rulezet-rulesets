rule Win_Trojan_Trivial_82
{
strings:
	$a0 = { ac0101b8014333c98d541ecd21b8023dcd2193b440b9bb00ba0001cd21b801578b4c168b5418 }


condition:
	$a0
}