rule Win_Trojan_Mutant_3
{
strings:
	$a0 = { 065a52b440cd21b43ecd210e1fb44f }


condition:
	$a0
}