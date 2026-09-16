rule Win_Trojan_Ontario_5
{
strings:
	$a0 = { 02b440e83300721733c933d2b80042e82700720bba0802b91b00b440e81a008b1606028b0e04 }


condition:
	$a0
}