rule Win_Trojan_AAEH_11
{
strings:
	$a0 = { 2d433030302d73796e7173 }

	$a1 = { 8d50ffffff3b4810730cc78530ffffff00000000eb0cff157c004100898530ffffff8b9550ffffffc1e20489952cffff }


condition:
	$a0 and $a1
}