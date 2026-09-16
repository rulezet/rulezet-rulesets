rule Win_Trojan_Daemaen_2
{
strings:
	$a0 = { e800005e81eed107b99207b80929310446fec0fecce2f7c3 }


condition:
	$a0
}