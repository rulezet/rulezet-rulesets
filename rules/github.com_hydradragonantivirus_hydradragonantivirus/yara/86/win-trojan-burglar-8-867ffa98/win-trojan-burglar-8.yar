rule Win_Trojan_Burglar_8
{
strings:
	$a0 = { b440cd21b000e83700ba4103b91800b440cd21b42ccd2180f90a7521bee002b800b08ed833 }


condition:
	$a0
}