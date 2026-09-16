rule Win_Trojan_Trivial_249
{
strings:
	$a0 = { b44e33c98d162401cd21b8023dba9e00cd2193b440b92a008d160001cd21b43ecd21cd20 }


condition:
	$a0
}