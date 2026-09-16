rule Win_Trojan_Trident_3
{
strings:
	$a0 = { de7504b8aaaacf80fc11743e80fc12743980fc4e7437 }


condition:
	$a0
}