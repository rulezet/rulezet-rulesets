rule Win_Trojan_Jam_1
{
strings:
	$a0 = { 5d81ed0e045351061ebb2c00268b078ed833db833f00740343ebf883c3048bd3b80043cd217303e98d0083e1fe }


condition:
	$a0
}