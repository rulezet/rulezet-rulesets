rule Win_Trojan_I13_24
{
strings:
	$a0 = { f112430f3a1b4f0d2cc0d6073779f4e4320d4f1e3ac0d6303a1e820e1eb5f70b4f2cc2c0d6237e93 }


condition:
	$a0
}