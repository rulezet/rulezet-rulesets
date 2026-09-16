rule Win_Trojan_Trivial_293
{
strings:
	$a0 = { 2a01b92700cd217219b42fcd2189de8d541eb8023dcd2193b93000ba0001b440cd21b8414ccd212a2e434f4d00 }


condition:
	$a0
}