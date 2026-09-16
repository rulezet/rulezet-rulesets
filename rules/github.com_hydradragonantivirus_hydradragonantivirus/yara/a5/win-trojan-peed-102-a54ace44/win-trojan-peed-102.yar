rule Win_Trojan_Peed_102
{
strings:
	$a0 = { fce86b000000ba010000004a87ca83c40583ec }


condition:
	$a0
}