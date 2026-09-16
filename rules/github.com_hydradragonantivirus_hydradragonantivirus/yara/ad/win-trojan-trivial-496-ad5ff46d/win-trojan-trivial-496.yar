rule Win_Trojan_Trivial_496
{
strings:
	$a0 = { 55e806005db8004ccd21b44eb92700ba1e01cd217203e80700c32a2e434f4d00b42fcd218bf3c706a6010000 }


condition:
	$a0
}