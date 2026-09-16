rule Win_Dropper_Agent_34097
{
strings:
	$a0 = { 78037901eb6053bb16f700005be80000 }


condition:
	$a0
}