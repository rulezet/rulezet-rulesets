rule Win_Trojan_BFD_1
{
strings:
	$a0 = { 2e8e55f82e8b65fafb2eff6dfc9c80fcf07504b4199d }


condition:
	$a0
}