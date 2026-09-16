rule Win_Trojan_B_77
{
strings:
	$a0 = { d0bc007c8ed8b84754cd13fca113044848a31304b106d3e08ec0be007c }


condition:
	$a0
}