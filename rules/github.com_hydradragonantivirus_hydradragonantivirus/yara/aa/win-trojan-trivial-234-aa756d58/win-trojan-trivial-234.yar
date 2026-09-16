rule Win_Trojan_Trivial_234
{
strings:
	$a0 = { ba2301cd217220b8013dba9e00cd21b740ba000193b12acd21b43ecd21b44febdf }


condition:
	$a0
}