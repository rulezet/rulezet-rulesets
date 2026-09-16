rule Win_Trojan_Tie_3
{
strings:
	$a0 = { 029033d2b4409c2eff1e1e00b442b00033c933d29c2eff1e1e00b90300ba2a00b4409c2eff1e }


condition:
	$a0
}