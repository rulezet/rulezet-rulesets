rule Win_Trojan_Rat_2
{
strings:
	$a0 = { cd2106532e8b3e01018bd781c2d702b41acd21b44e8bd781c22d03b91000cd21731ce949018bd781c2d702b4 }


condition:
	$a0
}