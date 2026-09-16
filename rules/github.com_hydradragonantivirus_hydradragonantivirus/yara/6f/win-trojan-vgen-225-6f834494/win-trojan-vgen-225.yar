rule Win_Trojan_VGEN_225
{
strings:
	$a0 = { 5e83ee032e89b46502b8ebf0cd21a102002d0003c41e0a002e899c60022e8c846202c7060a002a02a30c001e0e }


condition:
	$a0
}