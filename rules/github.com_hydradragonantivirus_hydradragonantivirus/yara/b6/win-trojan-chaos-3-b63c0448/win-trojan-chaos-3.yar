rule Win_Trojan_Chaos_3
{
strings:
	$a0 = { 656e63203d206d6964286272616e6465642c636f756e7465722c3129 }

	$a1 = { 633a5c6368616f737068657265 }


condition:
	$a0 and $a1
}