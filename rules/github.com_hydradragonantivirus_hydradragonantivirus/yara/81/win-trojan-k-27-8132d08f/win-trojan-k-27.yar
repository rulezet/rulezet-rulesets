rule Win_Trojan_K_27
{
strings:
	$a0 = { cd217233ba1001b93603908b1e0403b440cd217222b90000ba00008b1e0403b000b442cd217210 }


condition:
	$a0
}