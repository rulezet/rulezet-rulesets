rule Win_Trojan_Trivial_227
{
strings:
	$a0 = { b44eba2401cd217215b8023dba9e00cd2193b440b92800ba0001cd21b44febe5c3 }


condition:
	$a0
}