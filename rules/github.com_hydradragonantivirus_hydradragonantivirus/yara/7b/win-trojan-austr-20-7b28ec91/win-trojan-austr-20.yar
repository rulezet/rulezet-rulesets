rule Win_Trojan_Austr_20
{
strings:
	$a0 = { 40ba0001b94c02cd21b8004233d233c9cd21b440b90400 }


condition:
	$a0
}