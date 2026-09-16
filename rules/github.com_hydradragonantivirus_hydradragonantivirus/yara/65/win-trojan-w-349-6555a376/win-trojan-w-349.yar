rule Win_Trojan_W_349
{
strings:
	$a0 = { 09d957e9e3ccffff0000000000000000000000000000b9443ccb80e985d3ffff }


condition:
	$a0
}