rule Win_Trojan_Trivial_539
{
strings:
	$a0 = { b44eba????cd21b8023dba????cd2193b440ba0001cd21c3 }


condition:
	$a0
}