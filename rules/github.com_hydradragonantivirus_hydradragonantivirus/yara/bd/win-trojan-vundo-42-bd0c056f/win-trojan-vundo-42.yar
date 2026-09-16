rule Win_Trojan_Vundo_42
{
strings:
	$a0 = { e8190c00000f85e201000060be009007108dbe4dcdb5b21ace80b2a640ddddddc74b0bc54a0a4c96384ac653cea3b15c963fa0f54c4d4d4d4c96 }


condition:
	$a0
}