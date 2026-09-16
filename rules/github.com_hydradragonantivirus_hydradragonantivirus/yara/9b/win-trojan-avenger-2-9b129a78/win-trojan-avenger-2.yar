rule Win_Trojan_Avenger_2
{
strings:
	$a0 = { 616e4469736b2490eba6a8a920aaabaee3ad2c20a7a0aaa0e22c20a7aeabaee2a8e1e2e3ee20 }


condition:
	$a0
}