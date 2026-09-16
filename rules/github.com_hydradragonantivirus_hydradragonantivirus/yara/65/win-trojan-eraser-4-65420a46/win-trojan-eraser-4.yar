rule Win_Trojan_Eraser_4
{
strings:
	$a0 = { 8ec0e86c00e8640083fa01740fb409ba4100cd21ba0200cd21eb3f90ba4100b409cd2133c9e87f008bd7b002b4 }


condition:
	$a0
}