rule Win_Trojan_Macedonia_3
{
strings:
	$a0 = { 05b440b99001e870ffcd21b442b000b90000ba0000cd21 }


condition:
	$a0
}