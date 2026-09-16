rule Win_Trojan_Sailor_10
{
strings:
	$a0 = { ebf05e56ebec5e0e07b80102bb007eba8000b90400cd13b80103b90100cd1333c048504050cb }


condition:
	$a0
}