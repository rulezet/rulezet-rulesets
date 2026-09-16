rule Win_Trojan_Triv_2
{
strings:
	$a0 = { 0700ba5701cd217246b8023dba9e00cd2193b440b1dfba0001cd21b43ecd21b44febe2b42a }


condition:
	$a0
}