rule Win_Trojan_Stalkdaily_2
{
strings:
	$a0 = { 706f737420222b7375726c2b22 }

	$a1 = { 2f782e7068703f633d22202b20636f6f6b6965 }

	$a2 = { 6d7570646174655b355d3d224074776974746572 }


condition:
	$a0 and $a1 and $a2
}