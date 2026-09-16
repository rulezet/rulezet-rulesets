rule Win_Trojan_Albania_7
{
strings:
	$a0 = { 5e028bd583ea08b440cd2133ffeb03 }


condition:
	$a0
}