rule Win_Trojan_V_25
{
strings:
	$a0 = { d106be2001a0f107300446e2f8c38cc805bd0d50b81a0150cb1e0e1fe8e0ff }


condition:
	$a0
}