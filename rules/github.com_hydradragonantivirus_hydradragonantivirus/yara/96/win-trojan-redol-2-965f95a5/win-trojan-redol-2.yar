rule Win_Trojan_Redol_2
{
strings:
	$a0 = { 558bec6aff68fa20001468f31e001464a100000000506489250000000081 }

	$a1 = { 26533d7d5f39741b56 }


condition:
	$a0 and $a1
}