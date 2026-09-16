rule Win_Trojan_Keygen_9
{
strings:
	$a0 = { 558bec6aff6818e24000688c9a400064a1 }

	$a1 = { 4b657947656e20666f7220496e746572766964656f }


condition:
	$a0 and $a1
}