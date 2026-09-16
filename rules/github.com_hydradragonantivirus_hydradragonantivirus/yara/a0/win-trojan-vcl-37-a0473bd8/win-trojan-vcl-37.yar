rule Win_Trojan_VCL_37
{
strings:
	$a0 = { b9eb09b805feebfc80c43bebf41e2bc050b42acd21 }


condition:
	$a0
}