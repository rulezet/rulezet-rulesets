rule Win_Spyware_14456_1
{
strings:
	$a0 = { 0da4490000603dd0100000e80b0000008b }


condition:
	$a0
}