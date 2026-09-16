rule Win_Trojan_Peed_139
{
strings:
	$a0 = { e8000000008d642404e892000000f7db29dff7db01de89c3eb15 }


condition:
	$a0
}