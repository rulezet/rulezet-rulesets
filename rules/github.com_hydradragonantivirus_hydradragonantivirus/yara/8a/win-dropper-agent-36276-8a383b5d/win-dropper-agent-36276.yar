rule Win_Dropper_Agent_36276
{
strings:
	$a0 = { ffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc }


condition:
	$a0
}