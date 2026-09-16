rule Win_Trojan_COM200A_1
{
strings:
	$a0 = { 7b07e83e00ba8307b91c00b440cd2126c74515000026c745170000ba6707b440cd21268b4d }


condition:
	$a0
}