rule Win_Trojan_Trivial_291
{
strings:
	$a0 = { ba2a01b92700cd217219b42fcd2189deb8023d8d541ecd2193b440b93000ba0001cd21b8414ccd21 }


condition:
	$a0
}