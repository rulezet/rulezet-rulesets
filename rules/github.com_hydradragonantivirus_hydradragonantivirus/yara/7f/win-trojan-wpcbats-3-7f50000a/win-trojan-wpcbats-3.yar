rule Win_Trojan_WpcBats_3
{
strings:
	$a0 = { ecd1e7d1e7ac32078846002630450283ef044c81fc470174040bff74d8bc289314f8c243d2cb }


condition:
	$a0
}