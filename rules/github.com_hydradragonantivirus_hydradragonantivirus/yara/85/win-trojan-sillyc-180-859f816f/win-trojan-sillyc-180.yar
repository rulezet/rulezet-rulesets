rule Win_Trojan_SillyC_180
{
strings:
	$a0 = { b90300cd21b8004233c92e8b169a0083c229cd21b4 }


condition:
	$a0
}