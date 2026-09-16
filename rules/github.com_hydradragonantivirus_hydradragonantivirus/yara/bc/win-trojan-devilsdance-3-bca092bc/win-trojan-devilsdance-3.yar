rule Win_Trojan_DevilsDance_3
{
strings:
	$a0 = { cd2126807ffd44750f26807ffe7275 }


condition:
	$a0
}