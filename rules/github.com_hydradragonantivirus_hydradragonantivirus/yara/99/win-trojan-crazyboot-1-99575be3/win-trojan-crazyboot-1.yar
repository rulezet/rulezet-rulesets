rule Win_Trojan_CrazyBoot_1
{
strings:
	$a0 = { c08ed0bc007cb80202bb007eb90e00ba0001cd1372e7ea607e0000 }


condition:
	$a0
}