rule Win_Trojan_ELCN_2
{
strings:
	$a0 = { 5152565733f6bf54ecb90001fcf3a4b90e00e8ac00e871008cc8a39002be7802bf60eab96400fcf3a433ffbe54ec }


condition:
	$a0
}