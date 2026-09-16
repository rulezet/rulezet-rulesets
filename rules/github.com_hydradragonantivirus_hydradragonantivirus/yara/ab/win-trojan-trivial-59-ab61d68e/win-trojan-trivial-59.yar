rule Win_Trojan_Trivial_59
{
strings:
	$a0 = { 8bdbb44eb90000ba6f01cd21720ee818007504b44febf3b8004ccd21b840008ec0bf4a00b051aacd20 }


condition:
	$a0
}