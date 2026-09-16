rule Win_Trojan_Trivial_413
{
strings:
	$a0 = { 8a1e8000c687810000ba8200b8023dcd219387d6b440cd21c3 }


condition:
	$a0
}