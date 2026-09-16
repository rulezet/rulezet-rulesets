rule Win_Trojan_Trivial_153
{
strings:
	$a0 = { 1a01cd21b8023dba9e00cd2193b440b120ba0001cd21c32a2e636f6d }


condition:
	$a0
}