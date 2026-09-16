rule Win_Trojan_Albania_6
{
strings:
	$a0 = { 3f028bd583ea0eb440cd2133ffeb03 }


condition:
	$a0
}