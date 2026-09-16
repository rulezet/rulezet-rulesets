rule Win_Trojan_Hydra_16
{
strings:
	$a0 = { f3a4b41aba3501cd21b44eba2901cd21 }


condition:
	$a0
}