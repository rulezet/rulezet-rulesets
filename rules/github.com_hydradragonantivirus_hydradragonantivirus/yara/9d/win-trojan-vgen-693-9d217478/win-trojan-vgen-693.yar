rule Win_Trojan_VGEN_693
{
strings:
	$a0 = { eb00e800005d81ed060150535152565755061eb8cdabcd2181fbcdab74640e1f8cc1b82135cd212e8c8609022e899e07 }


condition:
	$a0
}