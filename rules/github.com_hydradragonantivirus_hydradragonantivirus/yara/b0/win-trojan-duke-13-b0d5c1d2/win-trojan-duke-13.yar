rule Win_Trojan_Duke_13
{
strings:
	$a0 = { 636f7079202f62202e6261742b2025323e6e756c2064656c203a65 }

	$a1 = { 5b696e76616465725d }


condition:
	$a0 and $a1
}