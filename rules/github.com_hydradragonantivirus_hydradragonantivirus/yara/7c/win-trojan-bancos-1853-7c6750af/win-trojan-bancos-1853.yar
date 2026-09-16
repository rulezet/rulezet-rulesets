rule Win_Trojan_Bancos_1853
{
strings:
	$a0 = { f721415133fcba9ce7cd00cf11ce7d98b8cdf7cb717f619b3b1ed9e5762d5ec626bc77113f10aecd250eff0844f7d8384af2dbdcd5c22e10d9fdc53499a9ccdba3772251b669 }


condition:
	$a0
}