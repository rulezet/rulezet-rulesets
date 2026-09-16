rule Win_Trojan_VGEN_285
{
strings:
	$a0 = { 210e1f1e07891ec002c606ff020090fcbef002bfe302b90d00f3a4be030333d2b447cd21b9050051e86401e881 }


condition:
	$a0
}