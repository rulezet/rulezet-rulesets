rule Win_Trojan_Nympho_1
{
strings:
	$a0 = { 5dcd213d3d00745c998eda87fac50684002e89860e022e8c9e10028cc0488ed8 }


condition:
	$a0
}