rule Win_Dropper_Agent_35578
{
strings:
	$a0 = { 558bec6aff68e070400068683d400064a100000000506489250000000083 }


condition:
	$a0
}