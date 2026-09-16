rule Win_Trojan_Spe_1
{
strings:
	$a0 = { 525657b8b98ebbe660b9b0f550535189260400cd01 }


condition:
	$a0
}