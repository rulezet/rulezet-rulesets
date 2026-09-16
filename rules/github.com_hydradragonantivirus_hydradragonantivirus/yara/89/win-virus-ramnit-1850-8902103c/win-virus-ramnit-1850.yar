rule Win_Virus_Ramnit_1850
{
strings:
	$a0 = { 83ec0460b??0000000 }


condition:
	$a0
}