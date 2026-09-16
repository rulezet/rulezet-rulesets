rule Win_Dropper_Agent_35391
{
strings:
	$a0 = { bb4356345381c3bc0ef09c53b82a5aa51381c02efeb24450ffd4b8fbf03c0081c0068f030050b81600 }


condition:
	$a0
}