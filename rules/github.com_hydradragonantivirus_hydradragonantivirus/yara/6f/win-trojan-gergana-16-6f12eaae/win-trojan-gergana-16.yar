rule Win_Trojan_Gergana_16
{
strings:
	$a0 = { ad013bca74e1b8024233c933d2cd21a3ab01b4 }


condition:
	$a0
}