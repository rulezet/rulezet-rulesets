rule Win_Trojan_Trivial_3
{
strings:
	$a0 = { b44eba2901cd217216ba9e00b8013dcd2189c3b93300b440ba0001cd217302cd20b43ecd21b44febd92a2e434f4d004d722e58 }


condition:
	$a0
}