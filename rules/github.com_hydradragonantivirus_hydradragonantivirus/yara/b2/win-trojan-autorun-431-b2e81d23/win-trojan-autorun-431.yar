rule Win_Trojan_Autorun_431
{
strings:
	$a0 = { 65786563757465286128616f2929 }

	$a1 = { 63203d206d69[0-16]206c656e28632929 }

	$a2 = { 6d696428642c20652c203229 }


condition:
	$a0 and $a1 and $a2
}