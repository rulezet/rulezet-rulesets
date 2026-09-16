rule Win_Trojan_Peed_22
{
strings:
	$a0 = { d1ec037e067fbcf9a63e027ece0cd3b2 }


condition:
	$a0
}