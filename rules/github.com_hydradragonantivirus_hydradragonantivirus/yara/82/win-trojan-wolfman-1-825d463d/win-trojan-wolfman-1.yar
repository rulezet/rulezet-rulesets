rule Win_Trojan_Wolfman_1
{
strings:
	$a0 = { 0e07cd1c83ec065883c4042d0400cc50 }


condition:
	$a0
}