rule Win_Trojan_Burglar_7
{
strings:
	$a0 = { b440cd21b000e83700ba3803b91800b440cd21b42ccd2180f9097521bedd02b800b08ed833 }


condition:
	$a0
}