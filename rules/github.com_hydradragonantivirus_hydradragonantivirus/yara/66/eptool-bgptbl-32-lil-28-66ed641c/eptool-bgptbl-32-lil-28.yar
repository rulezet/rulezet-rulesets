rule epTool_bgptbl__32_lil_28_
{
strings:
	$a0 = { af8f0000d52616001300000037050000e30a00000b000000e9000000 }

condition:
	$a0
}