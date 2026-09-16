rule Win_Dropper_Agent_34153
{
strings:
	$a0 = { 9f98989b9f989f }


condition:
	$a0
}