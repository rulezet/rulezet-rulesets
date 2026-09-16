rule Win_Trojan_VGEN_740
{
strings:
	$a0 = { e800005d81ed0b00b885ddcd2181fa12b074348cc0488ed8812e0300c000812e1200c0008e0612000e1f33ff8bf5 }


condition:
	$a0
}