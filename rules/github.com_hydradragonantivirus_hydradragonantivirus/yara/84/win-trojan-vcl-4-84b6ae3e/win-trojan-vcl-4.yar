rule Win_Trojan_VCL_4
{
strings:
	$a0 = { e800005d81ed06018db65702bf000157a5a48bfd8bec81ec8000b42fcd2153b41a8d5680cd21 }


condition:
	$a0
}