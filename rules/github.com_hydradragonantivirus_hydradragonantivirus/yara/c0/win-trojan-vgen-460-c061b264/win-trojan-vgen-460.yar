rule Win_Trojan_VGEN_460
{
strings:
	$a0 = { 83ee3c065633ffb80633cd21fec07461b452cd2126c577128b441f407453488ed8397d017507 }


condition:
	$a0
}