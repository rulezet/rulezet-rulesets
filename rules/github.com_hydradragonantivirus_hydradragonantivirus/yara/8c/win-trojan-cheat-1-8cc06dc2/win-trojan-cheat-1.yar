rule Win_Trojan_Cheat_1
{
strings:
	$a0 = { 01010055ed00000000ffff000000009a000000050000000f0300 }


condition:
	$a0
}