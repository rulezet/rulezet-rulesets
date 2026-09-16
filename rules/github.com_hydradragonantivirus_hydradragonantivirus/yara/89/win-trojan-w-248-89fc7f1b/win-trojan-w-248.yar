rule Win_Trojan_W_248
{
strings:
	$a0 = { 86138d502bdd401acd2009008b04fec4 }


condition:
	$a0
}