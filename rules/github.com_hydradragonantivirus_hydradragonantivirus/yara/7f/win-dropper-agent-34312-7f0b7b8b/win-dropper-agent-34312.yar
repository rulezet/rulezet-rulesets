rule Win_Dropper_Agent_34312
{
strings:
	$a0 = { 81fb8d8dc1e6541c46372f621431e3365573 }


condition:
	$a0
}