rule Win_Trojan_KillHDD_4
{
strings:
	$a0 = { b002b90900ba0000bb00008edabb0000cd26 }


condition:
	$a0
}