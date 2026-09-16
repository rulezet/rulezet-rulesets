rule Win_Trojan_Poly386_1
{
strings:
	$a0 = { a30a00f0b440bb1300c6061b0875bfb508be7d0ae81b03c326c7068d0a7f09 }


condition:
	$a0
}