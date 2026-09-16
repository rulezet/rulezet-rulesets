rule Win_Trojan_IntTrivialWe_1
{
strings:
	$a0 = { 4eba2101cd217301c3b8023dba9e00cd2193b12db440cd21b43ecd21b44febe1 }


condition:
	$a0
}