rule Win_Trojan_Plastique_7
{
strings:
	$a0 = { 2435cd21891e3c008c063e00baab02b8 }


condition:
	$a0
}