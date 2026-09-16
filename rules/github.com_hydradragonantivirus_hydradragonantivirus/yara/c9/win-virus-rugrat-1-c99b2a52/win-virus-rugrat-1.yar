rule Win_Virus_Rugrat_1
{
strings:
	$a0 = { 4d5a }

	$a1 = { 7267622e323961 }


condition:
	$a0 and $a1
}