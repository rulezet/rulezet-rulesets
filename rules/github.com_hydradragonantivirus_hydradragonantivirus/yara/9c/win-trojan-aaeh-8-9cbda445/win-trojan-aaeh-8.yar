rule Win_Trojan_AAEH_8
{
strings:
	$a0 = { 5a6f494d }

	$a1 = { 1a62e2404b6bbebe2ad720bddea1625e82449e4345b96713d869d2a19de9425a1ff53d5d6382846e3064681573898c68 }


condition:
	$a0 and $a1
}