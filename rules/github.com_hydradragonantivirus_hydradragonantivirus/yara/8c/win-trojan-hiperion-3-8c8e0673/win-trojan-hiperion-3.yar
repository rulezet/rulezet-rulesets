rule Win_Trojan_Hiperion_3
{
strings:
	$a0 = { 1d00bab10003d5b90500b440cd21e81800b9f9008bd5b440cd21b43ecd21c3 }


condition:
	$a0
}