rule Win_Trojan_DemonhyakG_1
{
strings:
	$a0 = { bab301b44eb90b11cd21907302eb11e84900ba8000 }


condition:
	$a0
}