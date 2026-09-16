rule Win_Trojan_Trivial_464
{
strings:
	$a0 = { 8bf3b8014333c98d541ecd21b8023dcd2193b440b940 }


condition:
	$a0
}