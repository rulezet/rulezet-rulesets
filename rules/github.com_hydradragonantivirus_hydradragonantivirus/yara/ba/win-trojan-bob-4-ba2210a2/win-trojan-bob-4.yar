rule Win_Trojan_Bob_4
{
strings:
	$a0 = { b789d783c75dab93b440b90400ba0001cd21b44089fe83c6fc81040001b9020089f2cd218b04 }


condition:
	$a0
}