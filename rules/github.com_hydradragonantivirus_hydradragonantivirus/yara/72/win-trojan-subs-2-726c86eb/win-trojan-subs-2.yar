rule Win_Trojan_Subs_2
{
strings:
	$a0 = { 6d6420633a5c73756273 }

	$a1 = { 636f707920253020256d25 }

	$a2 = { 5c2a2e6261742920646f20636f707920253020252577 }


condition:
	$a0 and $a1 and $a2
}