rule Win_Trojan_VGEN_457
{
strings:
	$a0 = { 1fbe4303ac0c007406b40ecd10ebf5b43232d2cd217216e89202e8ac028b5710b419cd21b90200 }


condition:
	$a0
}