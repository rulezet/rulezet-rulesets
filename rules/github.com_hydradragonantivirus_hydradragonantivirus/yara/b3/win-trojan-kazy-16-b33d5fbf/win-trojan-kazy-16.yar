rule Win_Trojan_Kazy_16
{
strings:
	$a0 = { 558bec8b0dfcab5a0066b87c008b3d2cac5a0029ff813d38ac5a009b000000721ba3f4aa5a008b1508ad5a0066b901 }


condition:
	$a0
}