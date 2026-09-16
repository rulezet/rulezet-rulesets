rule Win_Dropper_Agent_35657
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d }

	$a1 = { 4931494663303e354948513621 }

	$a2 = { 09785a500a785a580a785a381b7a5a4a187a5a }


condition:
	$a0 and $a1 and $a2
}