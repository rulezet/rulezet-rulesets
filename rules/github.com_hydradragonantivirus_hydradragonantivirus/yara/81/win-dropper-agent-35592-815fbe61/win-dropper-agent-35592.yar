rule Win_Dropper_Agent_35592
{
strings:
	$a0 = { 558bec6aff6800a1400068e04e400064a10000000050648925000000 }

	$a1 = { 6d6b646972 }

	$a2 = { 5c612e747874 }


condition:
	$a0 and $a1 and $a2
}