rule Win_Trojan_Unkm_3
{
strings:
	$a0 = { 010ac0c3b43ecd21b80043b900008d969e00cd21898eab00b80143b90000cd21b8023d8d969e }


condition:
	$a0
}