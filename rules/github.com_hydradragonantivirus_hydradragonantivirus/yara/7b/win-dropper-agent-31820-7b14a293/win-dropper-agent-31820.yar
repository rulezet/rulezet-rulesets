rule Win_Dropper_Agent_31820
{
strings:
	$a0 = { 68f82040008d85f0fdffff5650e8f2feffff }


condition:
	$a0
}