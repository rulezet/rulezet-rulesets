rule Win_Trojan_Wolfman_2
{
strings:
	$a0 = { cd1c83ec065883c4042d0400cc509c }


condition:
	$a0
}