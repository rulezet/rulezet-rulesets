rule Win_Trojan_Trivial_246
{
strings:
	$a0 = { 4eba0c01b120cd217305c32a2e2a00b8023dba9e00cd2193ba0001b12ab440cd21b43ecd21b44f }


condition:
	$a0
}