rule Win_Trojan_VB_1716
{
strings:
	$a0 = { 61730073636f6d63746c1a6b25c4190e454d914568f488de086a8b8d96b161a8b148 }


condition:
	$a0
}