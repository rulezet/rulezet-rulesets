rule Win_Trojan_Intended_3
{
strings:
	$a0 = { 03255acd21c47d0c4faafec6cd27 }


condition:
	$a0
}