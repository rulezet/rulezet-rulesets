rule Win_Trojan_V_109
{
strings:
	$a0 = { 40cd212e8b1e420333c933d2b80042cd210e1fb903002e8b1e4203ba4403b440cd212e8b1e4203 }


condition:
	$a0
}