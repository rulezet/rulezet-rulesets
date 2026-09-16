rule Win_Trojan_Peed_120
{
strings:
	$a0 = { 87d1b887d61200eb3ff7db29dff7db01de89c3e9a6000000ba0300000083ea024a87ca83c43783ec }


condition:
	$a0
}