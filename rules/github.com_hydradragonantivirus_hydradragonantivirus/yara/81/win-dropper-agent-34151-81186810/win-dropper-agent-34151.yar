rule Win_Dropper_Agent_34151
{
strings:
	$a0 = { 668bedb827c0ffffba71ffffff668bedbfb6c0ffff87d2bf1d104000668bed90 }


condition:
	$a0
}