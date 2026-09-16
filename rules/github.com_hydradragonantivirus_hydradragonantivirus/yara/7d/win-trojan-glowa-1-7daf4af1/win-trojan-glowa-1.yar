rule Win_Trojan_Glowa_1
{
strings:
	$a0 = { b8afffcd213dafaa7406e81b04e83f030e1fa128008b1e2a00071f8cd903c10510005053cb }


condition:
	$a0
}