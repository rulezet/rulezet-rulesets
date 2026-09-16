rule Win_Trojan_Swiss_7
{
strings:
	$a0 = { e800005981e9f97a51cbfb1e0e1fc606ac010007268b1e4c00 }


condition:
	$a0
}