rule Win_Trojan_Aussie_1
{
strings:
	$a0 = { b440b193ba0001cd21b43ecd21b44fcd2173d3c3 }


condition:
	$a0
}