rule Win_Trojan_Nazgul_1
{
strings:
	$a0 = { cd2f3d00fe7503eb1190b802febf554ebe4d44cd2f }


condition:
	$a0
}