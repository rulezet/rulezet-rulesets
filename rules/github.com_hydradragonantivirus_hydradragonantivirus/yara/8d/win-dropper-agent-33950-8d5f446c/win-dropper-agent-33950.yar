rule Win_Dropper_Agent_33950
{
strings:
	$a0 = { 558bec83c4f0535657b8009c4000e8d5b2ffff68789d40006a006a00e893b3ffff }


condition:
	$a0
}