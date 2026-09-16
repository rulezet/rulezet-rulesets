rule Win_Trojan_Trivial_151
{
strings:
	$a0 = { 20b44eba1b01cd21ba9e00b8013dcd2193b44940ba0001cd21c32a2e2a00 }


condition:
	$a0
}