rule Win_Trojan_SlamTilt_1
{
strings:
	$a0 = { d6b991028b1edcfdb440cd21a1c7fd25e1ff0d1e008bc88b16c9fd8b1edcfdb457b001cd21 }


condition:
	$a0
}