rule Win_Trojan_Corea_2
{
strings:
	$a0 = { 40b91c00ba4807e86afdb80042595acd21b440b9480733d2cd21b800428b16b0078b0eb207cd21 }


condition:
	$a0
}