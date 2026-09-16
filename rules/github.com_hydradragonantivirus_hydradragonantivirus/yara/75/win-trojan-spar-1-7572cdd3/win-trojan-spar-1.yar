rule Win_Trojan_Spar_1
{
strings:
	$a0 = { 3f8b0e2304bae8048b1e1b04cd217303e9ce00b4408b0e2304bae8048b1e1d04cd217303e9ba00 }


condition:
	$a0
}