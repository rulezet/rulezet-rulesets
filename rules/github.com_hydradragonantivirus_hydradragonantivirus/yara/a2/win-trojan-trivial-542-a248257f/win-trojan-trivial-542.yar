rule Win_Trojan_Trivial_542
{
strings:
	$a0 = { b44eba????cd21b8023dba????cd2193b440b1??ba0001cd21 }


condition:
	$a0
}