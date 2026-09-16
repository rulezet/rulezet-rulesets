rule Win_Trojan_ReplayII_1
{
strings:
	$a0 = { 81fe840275f3bd0000b430bb444dcd2181fb47520f845902b8003d8d96ea01cd210f834c02813e }


condition:
	$a0
}