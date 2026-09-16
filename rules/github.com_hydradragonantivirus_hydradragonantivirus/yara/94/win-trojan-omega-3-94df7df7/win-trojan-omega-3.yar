rule Win_Trojan_Omega_3
{
strings:
	$a0 = { aa897e2e83ec15b915008bfc8bf5 }


condition:
	$a0
}