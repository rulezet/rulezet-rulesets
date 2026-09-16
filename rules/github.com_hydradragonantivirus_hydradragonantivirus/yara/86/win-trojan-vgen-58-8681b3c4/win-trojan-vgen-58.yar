rule Win_Trojan_VGEN_58
{
strings:
	$a0 = { 138d1e1a018bd3cd2f1f891e59018c065b018d16de01cd2780fc02753e9c2eff1e590172319c26813f4d5a752826 }


condition:
	$a0
}