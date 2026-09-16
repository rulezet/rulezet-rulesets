rule Win_Trojan_Vecna_4
{
strings:
	$a0 = { 01b8010350b105cd135859bb0001cd13bedb02b91000ac34552ecd29e2f8b44c2ecd21be007c }


condition:
	$a0
}