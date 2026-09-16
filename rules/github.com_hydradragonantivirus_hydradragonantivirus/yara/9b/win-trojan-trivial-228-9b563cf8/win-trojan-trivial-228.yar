rule Win_Trojan_Trivial_228
{
strings:
	$a0 = { 33c9ba2201cd21b8023dba9e00cd2193b440b92800ba0001cd21b43ecd21cd20 }


condition:
	$a0
}