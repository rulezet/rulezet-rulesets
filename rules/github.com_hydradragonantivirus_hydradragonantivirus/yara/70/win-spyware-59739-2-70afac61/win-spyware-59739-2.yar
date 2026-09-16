rule Win_Spyware_59739_2
{
strings:
	$a0 = { 558bec83ec5056ff15441040008bf08a063c2275 }


condition:
	$a0
}