rule Win_Dropper_Agent_35971
{
strings:
	$a0 = { 60be007041008dbe00a0feff5783cdffeb109090909090908a06 }

	$a1 = { 726f6f742e726567 }

	$a2 = { 6f66745570646174652e626174 }


condition:
	$a0 and $a1 and $a2
}