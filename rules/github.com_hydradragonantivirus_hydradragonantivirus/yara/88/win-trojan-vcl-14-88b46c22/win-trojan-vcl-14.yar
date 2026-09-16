rule Win_Trojan_VCL_14
{
strings:
	$a0 = { 99cd2181fb99997403e90200cd20b82135cd212e891e }


condition:
	$a0
}