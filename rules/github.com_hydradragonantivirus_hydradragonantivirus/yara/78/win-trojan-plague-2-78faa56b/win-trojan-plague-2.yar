rule Win_Trojan_Plague_2
{
strings:
	$a0 = { 1e0e1f8cc82b061a018ec0be3d0bbf0001fca5a4 }


condition:
	$a0
}