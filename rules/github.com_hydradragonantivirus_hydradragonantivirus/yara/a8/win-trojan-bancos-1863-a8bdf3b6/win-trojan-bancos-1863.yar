rule Win_Trojan_Bancos_1863
{
strings:
	$a0 = { f72dc57fb9348298f3c0336ea69c47799d12bd203014fb698f656227c345e8fbb05f3c34a2615bde56df0e5122d3bc0904bee8923adca72e4ef35a9d0da0fb36e6ed6bb5eaba }


condition:
	$a0
}