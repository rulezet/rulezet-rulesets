rule Win_Trojan_VGEN_744
{
strings:
	$a0 = { e800005d81ed0b0033c08ec0bf0600abbf0e00abe4213402e6213402e621b83cbbcd2181fb5cf774348cc0488ed8 }


condition:
	$a0
}