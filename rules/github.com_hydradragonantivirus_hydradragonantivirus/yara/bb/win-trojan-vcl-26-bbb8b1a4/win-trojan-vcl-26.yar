rule Win_Trojan_VCL_26
{
strings:
	$a0 = { 0156b92905c704da15c644023b813433e44646e2f831f631c9c3 }


condition:
	$a0
}