rule Win_Trojan_Tula_3
{
strings:
	$a0 = { b43fcd217225bea00fac3c4d7505ac3c5a745cbe6e0281c6 }


condition:
	$a0
}