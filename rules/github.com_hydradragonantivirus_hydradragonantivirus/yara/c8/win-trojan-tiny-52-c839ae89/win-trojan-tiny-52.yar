rule Win_Trojan_Tiny_52
{
strings:
	$a0 = { fc4b7527505351521eb8014333c9cd21b8023dcd21930e1fb440b9ae00ba0001cd21b43ecd21 }


condition:
	$a0
}