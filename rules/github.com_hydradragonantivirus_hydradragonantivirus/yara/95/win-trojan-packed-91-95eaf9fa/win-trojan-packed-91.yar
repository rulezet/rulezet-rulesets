rule Win_Trojan_Packed_91
{
strings:
	$a0 = { e925e4ffff000000????????1e9c0600 }

	$a1 = { 161412ffc6bbabffcbaa88ffd5b593ffe3c8aaffe7d3bbffbe8c42ffbc8000ffcb9103ffd5a232ffdcb468ffe3c68dffddc69eff7dc9e1ffa7eaf9ff9ae7faff83dffbff67d4f6ff3dc8f9ff2ab8fbff89c1d8ffefe1cdffedd9be }


condition:
	$a0 and $a1
}