rule Win_Trojan_VCL_MUT_11
{
strings:
	$a0 = { b9eb09bbeb09b805feebfc80c43bebf4bb21010e07cd21b001cd21eb02ebfec606290182b080e621b9040051 }


condition:
	$a0
}