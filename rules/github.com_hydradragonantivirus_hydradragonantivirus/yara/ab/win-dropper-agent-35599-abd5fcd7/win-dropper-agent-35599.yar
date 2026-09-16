rule Win_Dropper_Agent_35599
{
strings:
	$a0 = { b87ce24e005064ff35000000006489250000000033c0890887 }


condition:
	$a0
}