rule Win_Trojan_Austr_24
{
strings:
	$a0 = { b9d602cd21b8004233d233c9cd21b440b90300ba0001 }


condition:
	$a0
}