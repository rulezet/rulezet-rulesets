rule Win_Dropper_Agent_35457
{
strings:
	$a0 = { 558bec6aff688820400068301f }

	$a1 = { 89abb1b189abb1b180bba7e3[0-8]4865726569746973 }


condition:
	$a0 and $a1
}