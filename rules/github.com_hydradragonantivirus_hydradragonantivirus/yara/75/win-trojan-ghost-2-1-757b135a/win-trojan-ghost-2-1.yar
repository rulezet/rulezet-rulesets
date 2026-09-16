rule Win_Trojan_Ghost_2_1
{
strings:
	$a0 = { 8c7a7df725739a618df8929a7c8d7c758ee7c672bf610074c67ac0f2bf617c756c75fa445b77f8b3 }


condition:
	$a0
}