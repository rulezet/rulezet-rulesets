rule Win_Dropper_Agent_35569
{
strings:
	$a0 = { 558becb81bfa4da0bb4b6b21f950e800000000582da81a0000b96d }


condition:
	$a0
}