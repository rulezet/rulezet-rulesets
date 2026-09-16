rule Win_Trojan_VGEN_675
{
strings:
	$a0 = { fae800005e83ee050e5650bbffffb44acd2181eb8f0053068cdd03dd8ec32bffb9230451560efcf32ea406b13051cb }


condition:
	$a0
}