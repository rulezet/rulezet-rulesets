rule Win_Trojan_Packed_28
{
strings:
	$a0 = { e9bcfbffff76a9b68f055f8563d3d47a }


condition:
	$a0
}