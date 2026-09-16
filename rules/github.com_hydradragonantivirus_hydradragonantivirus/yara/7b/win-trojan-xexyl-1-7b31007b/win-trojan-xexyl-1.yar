rule Win_Trojan_Xexyl_1
{
strings:
	$a0 = { fffa8ed7bc007cfb8bf4571fff0e1304cd12c1e0065007b90002fcf3a506b8620050cb }


condition:
	$a0
}