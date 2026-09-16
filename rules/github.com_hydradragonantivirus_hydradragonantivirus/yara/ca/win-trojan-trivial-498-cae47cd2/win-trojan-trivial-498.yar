rule Win_Trojan_Trivial_498
{
strings:
	$a0 = { 0155b44ecd217228b42fcd218bf3b8014333c98d541ecd21b8023dcd2193b440b93f00ba0001cd21b43ecd21b44febd45dcd202a2e2a00569993c28b90 }


condition:
	$a0
}