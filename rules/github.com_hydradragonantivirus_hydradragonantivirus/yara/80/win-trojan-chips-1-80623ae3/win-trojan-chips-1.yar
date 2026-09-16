rule Win_Trojan_Chips_1
{
strings:
	$a0 = { 1acd21b91100bb520280376443e2fab419cd21a24d02b4 }


condition:
	$a0
}