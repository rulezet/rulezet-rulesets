rule Win_Dropper_Sdbot_95
{
strings:
	$a0 = { 558bec6aff6830614000684053400064a100000000506489250000000083ec68 }


condition:
	$a0
}