rule Win_Trojan_Trivial_80
{
strings:
	$a0 = { eb11908b1eb301b9b20090ba0001b440cd21c3b44ebaa60133c9cd217203eb1a90b43bbaaa01cd21720eebe7b44f }


condition:
	$a0
}