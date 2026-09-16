rule Win_Trojan_VGEN_191
{
strings:
	$a0 = { bd04008d96e4048ac0ffd2d68e55c907f78efdb960e559985cdde37c78a3aedf8ba3aeddc37d78d9fb4878d5baf5fdba }


condition:
	$a0
}