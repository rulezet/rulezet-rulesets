rule Win_Trojan_R_66
{
strings:
	$a0 = { b466cd2181fb6666746b0e1fb44abba52581c35a }


condition:
	$a0
}