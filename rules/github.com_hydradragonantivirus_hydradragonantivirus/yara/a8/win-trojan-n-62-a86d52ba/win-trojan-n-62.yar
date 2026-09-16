rule Win_Trojan_N_62
{
strings:
	$a0 = { 8bf583ed0333ffbb7519b8ab1dcd2180fcab752584c07412b93c00b40fcd10b307acf6d0b40ecd10e2f7161f1607 }


condition:
	$a0
}