rule Win_Trojan_VGEN_719
{
strings:
	$a0 = { 9a02a58b2e9a0283c40281ed03010e1f8d96a002b43bcd217202eb01c30e1fb910008d963502b44ecd2172f00e }


condition:
	$a0
}