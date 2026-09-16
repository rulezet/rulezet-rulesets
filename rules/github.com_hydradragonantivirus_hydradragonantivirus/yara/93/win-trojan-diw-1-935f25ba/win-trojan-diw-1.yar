rule Win_Trojan_DIW_1
{
strings:
	$a0 = { e93400dd2a2e636f6d00e933000080005ab42abf00018bf283c60ab90400f3a452b42fcd218bfa2e895d0e81c2 }


condition:
	$a0
}