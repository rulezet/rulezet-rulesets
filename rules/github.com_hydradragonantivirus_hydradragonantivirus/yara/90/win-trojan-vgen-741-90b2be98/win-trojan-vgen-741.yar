rule Win_Trojan_VGEN_741
{
strings:
	$a0 = { 06e800005d81ed0b00b8d192cd2181fb782a74348cc0488ed8812e0300c000812e1200c0008e0612000e1f33ff8bf5 }


condition:
	$a0
}