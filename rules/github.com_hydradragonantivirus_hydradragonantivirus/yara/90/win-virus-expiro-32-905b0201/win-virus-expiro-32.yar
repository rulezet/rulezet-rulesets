rule Win_Virus_Expiro_32
{
strings:
	$a0 = { 60e8fd8a020061e9 }

	$a1 = { 044e4646 }


condition:
	$a0 and $a1
}