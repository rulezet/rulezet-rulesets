rule Win_Trojan_Trivial_266
{
strings:
	$a0 = { 4eba2701cd21721cb8023dba9e00cd2193b4408a0e4380ba0001cd21b43ecd21b44febe0cd20 }


condition:
	$a0
}