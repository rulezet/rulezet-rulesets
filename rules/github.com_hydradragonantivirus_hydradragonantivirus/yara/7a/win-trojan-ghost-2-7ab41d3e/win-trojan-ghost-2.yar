rule Win_Trojan_Ghost_2
{
strings:
	$a0 = { ae75ede2fa5e0789bc16008bfe81c71f }


condition:
	$a0
}