rule Win_Dropper_Agent_35609
{
strings:
	$a0 = { 558becb81662849ebbea186eb450e800000000582da81a0000b96d }

	$a1 = { 306e0d23302a60655d206d3d }

	$a2 = { 42722b4958 }


condition:
	$a0 and $a1 and $a2
}