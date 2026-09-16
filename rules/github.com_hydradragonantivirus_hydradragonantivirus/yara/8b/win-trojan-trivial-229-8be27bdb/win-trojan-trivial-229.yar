rule Win_Trojan_Trivial_229
{
strings:
	$a0 = { c9ba2201cd21b8023dba9e00cd2193b440ba0001b92800cd21b43ecd21cd20 }


condition:
	$a0
}