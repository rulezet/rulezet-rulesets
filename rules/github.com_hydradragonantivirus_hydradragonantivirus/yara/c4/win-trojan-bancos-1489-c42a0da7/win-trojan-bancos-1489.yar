rule Win_Trojan_Bancos_1489
{
strings:
	$a0 = { 795ef6d551e4e1df00ad27e7caaaadbb2337517d29a6587cf2bc02570f4b32e1b7e0778dc4d19560c0b9cbec0448b94a060c9c1b7607da2b5b038c03b27b7105d1be038621b7ee1baad7bdd5d5e427ac8bae }


condition:
	$a0
}