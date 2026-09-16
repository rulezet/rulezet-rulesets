rule Win_Trojan_Fich_V_4
{
strings:
	$a0 = { bb3101cf49e304cd01ebf9eb3f90 }


condition:
	$a0
}