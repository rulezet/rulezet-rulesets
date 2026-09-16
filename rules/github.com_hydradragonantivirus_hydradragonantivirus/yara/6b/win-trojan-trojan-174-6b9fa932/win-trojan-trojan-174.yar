rule Win_Trojan_Trojan_174
{
strings:
	$a0 = { b844008ec0bf00018bf7b93301f3a48ed9be8400bf3302 }


condition:
	$a0
}