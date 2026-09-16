rule Win_Trojan_Typo_4
{
strings:
	$a0 = { c0b4ddcd163ac4750258c35356068b }


condition:
	$a0
}