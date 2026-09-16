rule Win_Trojan_Wit_7
{
strings:
	$a0 = { 751480fa0f750fb81010e770bac602e81300b0fee6648a6605b107baba02cd21730ce9f400 }


condition:
	$a0
}