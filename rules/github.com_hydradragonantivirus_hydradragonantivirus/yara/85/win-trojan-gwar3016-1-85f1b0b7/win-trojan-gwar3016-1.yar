rule Win_Trojan_GWAR3016_1
{
strings:
	$a0 = { 1f890e070189160a0132e4cdfeb80103cdfe7231e83e00e440a2f301e83600061f0e07fc8bf3bf }


condition:
	$a0
}