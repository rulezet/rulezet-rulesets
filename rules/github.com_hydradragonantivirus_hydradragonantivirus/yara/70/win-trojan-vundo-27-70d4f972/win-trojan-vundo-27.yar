rule Win_Trojan_Vundo_27
{
strings:
	$a0 = { 807c2408015690eb }

	$a1 = { 50494e }


condition:
	$a0 and $a1
}