rule Win_Trojan_Darkmoon_9
{
strings:
	$a0 = { 6f6f6e250000ffffffff010000002a000000ffffffff0100000023000000ffffffff0100000031000000558bec6a0053bb2c }


condition:
	$a0
}