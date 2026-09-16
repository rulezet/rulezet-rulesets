rule Win_Trojan_SMEG_2
{
strings:
	$a0 = { 952f311f93473bbc3119984f35b37b3f202873a5165d17be8d }


condition:
	$a0
}