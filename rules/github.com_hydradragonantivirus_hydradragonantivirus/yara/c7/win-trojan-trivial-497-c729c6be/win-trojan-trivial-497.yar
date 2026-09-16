rule Win_Trojan_Trivial_497
{
strings:
	$a0 = { cd217228b42fcd218bf3b8014333c98d541ecd21b8023dcd2193b440b93d00ba0001cd21b43ecd21b44febd4 }


condition:
	$a0
}