rule Win_Trojan_ItaVir_1
{
strings:
	$a0 = { 0db01bbad10bb425cd21b000a2690d }


condition:
	$a0
}