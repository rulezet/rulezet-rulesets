rule Win_Trojan_Vgen_113
{
strings:
	$a0 = { 02e800005d81ed090150535152565755061eb8cdabcd2181fbcdab747d0e1f8cc1b80935cd212e8c86c5012e899ec3 }


condition:
	$a0
}