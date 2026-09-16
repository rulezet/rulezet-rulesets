rule Win_Dropper_Agent_35542
{
strings:
	$a0 = { 558bec83ec5cc745ec04000000c745f899af }

	$a1 = { 4a3652365a3662366a3672367a36c63c }


condition:
	$a0 and $a1
}