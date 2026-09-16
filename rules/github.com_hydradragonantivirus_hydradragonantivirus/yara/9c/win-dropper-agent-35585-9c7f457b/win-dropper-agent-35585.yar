rule Win_Dropper_Agent_35585
{
strings:
	$a0 = { e80a000000e97affffffcccccccccc8bff558bec }

	$a1 = { 626162796769726c2e657865 }


condition:
	$a0 and $a1
}