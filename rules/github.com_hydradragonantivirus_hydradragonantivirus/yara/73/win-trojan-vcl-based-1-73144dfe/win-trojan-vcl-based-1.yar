rule Win_Trojan_VCL_based_1
{
strings:
	$a0 = { 8100813434674646e2f8c3 }


condition:
	$a0
}