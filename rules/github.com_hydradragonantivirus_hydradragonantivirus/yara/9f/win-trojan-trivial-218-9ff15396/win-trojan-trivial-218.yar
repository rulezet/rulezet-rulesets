rule Win_Trojan_Trivial_218
{
strings:
	$a0 = { b44eba2301cd217301c3b43cba9e00cd2193b440b127ba0001cd21b43ecd21b44febe2 }


condition:
	$a0
}