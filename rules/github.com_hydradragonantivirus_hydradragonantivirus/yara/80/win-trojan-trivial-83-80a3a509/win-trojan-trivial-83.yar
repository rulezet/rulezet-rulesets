rule Win_Trojan_Trivial_83
{
strings:
	$a0 = { b41a8bd6cd21b40fba5c00cd21b415cd3fc3 }


condition:
	$a0
}