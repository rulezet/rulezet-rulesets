rule Win_Trojan_VGEN_470
{
strings:
	$a0 = { 585a3bd07561ba4559b801facd218d9e5802b90100ba8000b80102cd1326803fe87502eb1ab90200b80103cd13 }


condition:
	$a0
}