rule Win_Trojan_Trivial_38
{
strings:
	$a0 = { 1aba80002ecd21b44eb90700ba3a012ecd217303e91f00b8023dba9e002ecd218bd8b440ba0001b965002ecd21b43e }


condition:
	$a0
}