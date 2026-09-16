rule Win_Trojan_Trivial_195
{
strings:
	$a0 = { b44eba2101cd21b8013dba9e00cd2193b440b125ba0001cd21b43ecd21 }


condition:
	$a0
}