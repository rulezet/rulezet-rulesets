rule Win_Trojan_Peed_100
{
strings:
	$a0 = { e849000000f7db29dff7db01de89c3eb58 }


condition:
	$a0
}