rule Win_Dropper_Agent_35469
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d }

	$a1 = { 596f754675636b }

	$a2 = { 633a5c312e657865 }


condition:
	$a0 and $a1 and $a2
}