rule Win_Trojan_VGEN_742
{
strings:
	$a0 = { e800005d81ed0b0033c08ec0bf0600abbf0e00abe4213402e6213402e621b89dc2cd2181f9ce6d74398cc0488ed8 }


condition:
	$a0
}