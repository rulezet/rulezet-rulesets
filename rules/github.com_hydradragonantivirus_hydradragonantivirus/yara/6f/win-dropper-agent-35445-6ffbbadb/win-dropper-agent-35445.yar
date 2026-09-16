rule Win_Dropper_Agent_35445
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833da8 }

	$a1 = { 6563616165626178612e646c6c }


condition:
	$a0 and $a1
}