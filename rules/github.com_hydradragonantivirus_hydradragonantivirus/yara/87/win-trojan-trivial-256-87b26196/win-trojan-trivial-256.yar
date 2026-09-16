rule Win_Trojan_Trivial_256
{
strings:
	$a0 = { b44eba2601b92600cd217218b8023dba9e00cd21b92c00ba00018bd8b440cd21b43ecd21cd20 }


condition:
	$a0
}