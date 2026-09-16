rule Win_Trojan_Gula_5
{
strings:
	$a0 = { 33c933d2cd21b440b9c001ba0001cd21b43ecd21ebceb483cd2181fa99197405ba1f01cd27 }


condition:
	$a0
}