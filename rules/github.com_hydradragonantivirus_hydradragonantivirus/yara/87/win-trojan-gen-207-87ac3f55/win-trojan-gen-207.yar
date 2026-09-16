rule Win_Trojan_Gen_207
{
strings:
	$a0 = { 69fcb44f702d01a871f85515bcf271a30678717f71e3c3e95cff7af8bbfe078a25bd38c47509e1 }


condition:
	$a0
}