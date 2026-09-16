rule Win_Trojan_Sunrise_1
{
strings:
	$a0 = { 970321c6869803e98b8687032d050089869903c3b440cd21c3b43ecd21c3b43dcd21c3b80157 }


condition:
	$a0
}