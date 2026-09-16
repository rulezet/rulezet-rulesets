rule Win_Trojan_FullDead_2
{
strings:
	$a0 = { 018bf583c61f90b8e8042e8a1433d02e881446e2f5 }


condition:
	$a0
}