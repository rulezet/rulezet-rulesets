rule Win_Trojan_Trivial_182
{
strings:
	$a0 = { ba1f01cd217301c3b43cba9e00cd2193b440b123ba0001cd21b44febe62a2e2a00 }


condition:
	$a0
}