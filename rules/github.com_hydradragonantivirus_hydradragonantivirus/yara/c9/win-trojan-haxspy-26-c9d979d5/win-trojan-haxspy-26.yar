rule Win_Trojan_Haxspy_26
{
strings:
	$a0 = { 2e73796d613f636f5bc05da90064697f741e2e6d63d80d78f661666565136f7711616413 }


condition:
	$a0
}