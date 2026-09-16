rule Win_Trojan_Packed_151
{
strings:
	$a0 = { 508bc15883c40433c09090 }


condition:
	$a0
}