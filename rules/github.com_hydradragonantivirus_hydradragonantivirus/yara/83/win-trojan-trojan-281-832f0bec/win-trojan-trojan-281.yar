rule Win_Trojan_Trojan_281
{
strings:
	$a0 = { 21ba9e00b8013dcd21938bd6b11eb440cd21c32a2e2a00 }


condition:
	$a0
}