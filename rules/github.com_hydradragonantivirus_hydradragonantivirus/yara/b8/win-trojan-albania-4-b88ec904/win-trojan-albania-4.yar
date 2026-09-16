rule Win_Trojan_Albania_4
{
strings:
	$a0 = { ad018bd583ea04b440cd2133ffeb03 }


condition:
	$a0
}