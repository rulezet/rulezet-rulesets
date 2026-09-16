rule Win_Dropper_Agent_31744
{
strings:
	$a0 = { 68f450400050ffd683c40c8d85acfaffff53508d85acfeffff50ff1518404000 }


condition:
	$a0
}