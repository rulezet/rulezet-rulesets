rule Win_Trojan_PCBB_4
{
strings:
	$a0 = { b5b4e58675866e867c86678643864a8658bbbbb2aa }


condition:
	$a0
}