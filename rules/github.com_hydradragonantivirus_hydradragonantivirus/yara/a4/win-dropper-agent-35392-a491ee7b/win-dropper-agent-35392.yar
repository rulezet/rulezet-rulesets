rule Win_Dropper_Agent_35392
{
strings:
	$a0 = { 60be003041008dbe00e0feff57eb0b908a064688074701 }

	$a1 = { 5365784b65795365617263682e657865 }


condition:
	$a0 and $a1
}