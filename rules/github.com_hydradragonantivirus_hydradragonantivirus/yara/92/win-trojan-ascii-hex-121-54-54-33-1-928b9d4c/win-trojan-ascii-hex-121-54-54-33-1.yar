rule Win_Trojan_Ascii_Hex_121_54_54_33_1
{
strings:
	$a0 = { 792e362e362e21 }


condition:
	$a0
}