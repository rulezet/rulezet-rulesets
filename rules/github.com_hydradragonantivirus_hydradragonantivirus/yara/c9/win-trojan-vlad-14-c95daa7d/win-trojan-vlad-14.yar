rule Win_Trojan_VLAD_14
{
strings:
	$a0 = { e800005e83ee050e5650bbffffb44acd2181eb920053068cdd03dd8ec32bffb93d0451560efcf32ea406b13051cb }


condition:
	$a0
}