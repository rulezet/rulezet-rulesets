rule Win_Trojan_Enigma_3
{
strings:
	$a0 = { 03d3b8023dcd215b5a7303e96003be }


condition:
	$a0
}