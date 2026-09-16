rule Win_Trojan_Trivial_1
{
strings:
	$a0 = { b41a8bd6cd21b40fba5c00cd21b415cd21c3 }


condition:
	$a0
}