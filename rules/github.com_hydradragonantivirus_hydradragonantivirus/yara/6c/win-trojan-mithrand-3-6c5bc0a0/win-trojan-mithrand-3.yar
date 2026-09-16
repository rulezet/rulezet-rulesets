rule Win_Trojan_Mithrand_3
{
strings:
	$a0 = { c08ed8babd02b82125cd21cd00cd20930144654d6f5261 }


condition:
	$a0
}