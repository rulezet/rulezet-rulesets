rule Win_Trojan_Remor_3
{
strings:
	$a0 = { 1480fa0f750fb81010e770baa502e81300b0fee6648a6605b107ba9902cd21730ce9f300 }


condition:
	$a0
}