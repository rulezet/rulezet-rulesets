rule Win_Trojan_V_98
{
strings:
	$a0 = { fa0a75f0ba8000b90100fec5b80103cd1373f7eaf0ff00f03d9899746b3d004b741180fc43740c }


condition:
	$a0
}