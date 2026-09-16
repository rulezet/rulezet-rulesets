rule Win_Trojan_Dreamer_2
{
strings:
	$a0 = { fc1174b380fc1274ae3dab4275059df8ca02003d004b }


condition:
	$a0
}