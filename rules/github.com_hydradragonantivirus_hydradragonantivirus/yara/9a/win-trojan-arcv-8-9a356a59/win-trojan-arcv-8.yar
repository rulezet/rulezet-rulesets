rule Win_Trojan_Arcv_8
{
strings:
	$a0 = { fac3fe84dc01e8e3ffb4408d940901b9fa00e80400ebd5b43f8b9c0302cd21c3 }


condition:
	$a0
}