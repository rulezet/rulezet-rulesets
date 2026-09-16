rule Win_Dropper_Agent_35466
{
strings:
	$a0 = { e80a000000e97affffffcccccccccc8bff55 }

	$a1 = { 6d6f7669303064632807 }

	$a2 = { 626e657a2e657865 }


condition:
	$a0 and $a1 and $a2
}