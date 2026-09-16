rule Win_Trojan_VGEN_151
{
strings:
	$a0 = { 04cd1a80fe0875eab43cba9f03b92000cd219372ddb440bae203b9c007cd2172d1b43ecd21b44abb0040cd21b8004b }


condition:
	$a0
}