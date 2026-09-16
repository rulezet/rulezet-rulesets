rule Win_Trojan_Small_168
{
strings:
	$a0 = { ba0100eb58b802422bc92bd2cd2150b440b9c2008b160401cd21b440b90c00baf200cd215853 }


condition:
	$a0
}