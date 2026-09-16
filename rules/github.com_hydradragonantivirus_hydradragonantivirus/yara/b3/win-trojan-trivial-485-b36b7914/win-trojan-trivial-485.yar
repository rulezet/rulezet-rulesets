rule Win_Trojan_Trivial_485
{
strings:
	$a0 = { 83ee01e2fa2bc9ba4f17b40181ea0d1680f44f4fcd214eb8f311fcba75224781ead7214e35f12c47cd21 }


condition:
	$a0
}