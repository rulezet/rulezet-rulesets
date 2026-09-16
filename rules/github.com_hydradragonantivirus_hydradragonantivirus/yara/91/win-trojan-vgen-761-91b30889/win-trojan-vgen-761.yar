rule Win_Trojan_VGEN_761
{
strings:
	$a0 = { 0157e80300cd20905efcad93ac5053e82301e8030032c0cf5ab82425cd21b42fcd2106538bd683c203b41acd21e8 }


condition:
	$a0
}