rule Win_Trojan_Lviv_1
{
strings:
	$a0 = { f5020eeab5021c5053ba4c417ecba5ef4d714eeb8002f54070eaaf023e01a4c04d8995ba4d55a5d7 }


condition:
	$a0
}