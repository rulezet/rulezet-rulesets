rule Win_Trojan_Trivial_365
{
strings:
	$a0 = { 4401b8013dcd217206b95300e82500b120b44eba3e01cd217218ba9e00525e837cfe00 }


condition:
	$a0
}