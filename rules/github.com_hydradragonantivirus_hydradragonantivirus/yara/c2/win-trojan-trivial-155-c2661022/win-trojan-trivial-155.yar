rule Win_Trojan_Trivial_155
{
strings:
	$a0 = { 4eba1a01cd21b8023dba9e00cd2193b440b11fba0001cd21c3 }


condition:
	$a0
}