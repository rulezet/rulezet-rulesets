rule Win_Trojan_Trivial_4
{
strings:
	$a0 = { b44eba2901cd21721cba9e00b8013dcd2189c3b92d00b440ba0001cd21b43ecd21b44febddcd202a2e434f4d00 }


condition:
	$a0
}