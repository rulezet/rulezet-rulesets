rule Win_Trojan_DMSETU_1
{
strings:
	$a0 = { 04ff163214b440cd215f8be55dca020000530651b90004870e821151509a7b31ac005b8f06 }


condition:
	$a0
}