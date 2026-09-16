rule Win_Trojan_Erase26_1
{
strings:
	$a0 = { b402bb0000b98000ba0000cd26 }


condition:
	$a0
}