rule Win_Trojan_Deaf_1
{
strings:
	$a0 = { 01b9430490b440cd21ba8005b91c00b440cd2126c74515000026c745170000ba6405b440cd21 }


condition:
	$a0
}