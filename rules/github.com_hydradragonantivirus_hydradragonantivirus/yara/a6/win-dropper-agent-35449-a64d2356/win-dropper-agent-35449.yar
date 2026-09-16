rule Win_Dropper_Agent_35449
{
strings:
	$a0 = { 6a0068e718010068ed170100833c2400750b8d5424 }

	$a1 = { 6e746f736b726e6c2e657865 }

	$a2 = { 53616665204d6f6e20333630 }


condition:
	$a0 and $a1 and $a2
}