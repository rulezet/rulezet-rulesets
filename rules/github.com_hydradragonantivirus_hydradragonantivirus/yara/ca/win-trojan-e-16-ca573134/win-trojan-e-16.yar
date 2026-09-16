rule Win_Trojan_E_16
{
strings:
	$a0 = { be4c0056a5a55fb86202ab33c0abbb0300bd0500b8104a50 }


condition:
	$a0
}