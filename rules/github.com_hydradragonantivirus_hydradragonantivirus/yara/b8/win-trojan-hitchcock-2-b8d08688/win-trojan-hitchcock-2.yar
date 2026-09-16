rule Win_Trojan_Hitchcock_2
{
strings:
	$a0 = { b440b9df04badf05cd217226b8004233 }


condition:
	$a0
}