rule Win_Trojan_Mayhem_1
{
strings:
	$a0 = { 40b9c901ba6400cd21b801573e8b8eb1023e8b96b302cd21b43ecd2133c93e8a8eb002e80d00c3 }


condition:
	$a0
}