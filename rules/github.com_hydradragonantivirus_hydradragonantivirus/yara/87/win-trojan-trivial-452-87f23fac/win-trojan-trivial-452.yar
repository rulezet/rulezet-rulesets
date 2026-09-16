rule Win_Trojan_Trivial_452
{
strings:
	$a0 = { b92000ba2d01cd21b42fcd21061f8d571eb8023dcd218bd8b440b93400ba0001cd21b43ecd21b8004ccd21 }


condition:
	$a0
}