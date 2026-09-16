rule Win_Trojan_Trivial_101
{
strings:
	$a0 = { 2a2e434f4db44efec6cd21b8023dba9e00cd2193b440 }


condition:
	$a0
}