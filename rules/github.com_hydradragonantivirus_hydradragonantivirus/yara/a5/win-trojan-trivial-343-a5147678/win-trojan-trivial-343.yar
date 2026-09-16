rule Win_Trojan_Trivial_343
{
strings:
	$a0 = { 3dba9e00cd2193b440b1449090ba0001cd21b43ecd21 }


condition:
	$a0
}