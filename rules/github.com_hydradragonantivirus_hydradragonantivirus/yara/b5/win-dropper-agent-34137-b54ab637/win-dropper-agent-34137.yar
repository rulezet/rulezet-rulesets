rule Win_Dropper_Agent_34137
{
strings:
	$a0 = { 505083c40489142481eaea765d2d81c2 }


condition:
	$a0
}