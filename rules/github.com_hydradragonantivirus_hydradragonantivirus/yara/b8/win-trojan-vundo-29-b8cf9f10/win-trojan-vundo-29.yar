rule Win_Trojan_Vundo_29
{
strings:
	$a0 = { 807c2408015690eb }

	$a1 = { 5e83c6??668136????56c3000000000000000000000000000000000000 }


condition:
	$a0 and $a1
}