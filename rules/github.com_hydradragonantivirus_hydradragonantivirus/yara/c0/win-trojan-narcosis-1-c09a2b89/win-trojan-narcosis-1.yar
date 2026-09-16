rule Win_Trojan_Narcosis_1
{
strings:
	$a0 = { 5f07b440b9970599e8050226c74515000026c745170000b440b91a00ba9705e8ee01b801575a59 }


condition:
	$a0
}