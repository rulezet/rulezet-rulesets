rule Win_Trojan_Clicker_92
{
strings:
	$a0 = { 7768696c65286d78623c6e6a71297b7661726878746d3d[0-9]68726e3d22223b }

	$a1 = { 7a71633d34323030373b6d78622b2b3b }


condition:
	$a0 and $a1
}