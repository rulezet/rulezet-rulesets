rule Win_Trojan_VKit_6
{
strings:
	$a0 = { 01b82435cd212e891ee3022e8c06e502b425bafa01cd210e07b447b200bea302cd21ba4302e81f00ba4902b43bcd }


condition:
	$a0
}