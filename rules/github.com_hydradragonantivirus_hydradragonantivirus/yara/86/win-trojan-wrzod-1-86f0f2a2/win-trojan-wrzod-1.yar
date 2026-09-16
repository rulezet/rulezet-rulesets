rule Win_Trojan_Wrzod_1
{
strings:
	$a0 = { 6a00ba130483ea2033ff3e8aa60e053e28a31a01473bfa75f6 }


condition:
	$a0
}