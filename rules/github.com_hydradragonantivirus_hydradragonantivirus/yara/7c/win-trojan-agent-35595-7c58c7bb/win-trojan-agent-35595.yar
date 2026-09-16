rule Win_Trojan_Agent_35595
{
strings:
	$a0 = { 558bec6aff68e0304000682027400064a100000000506489250000000083 }

	$a1 = { 4f70656e[0-4]25735c2573 }


condition:
	$a0 and $a1
}