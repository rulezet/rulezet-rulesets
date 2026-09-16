rule Win_Trojan_Trivial_310
{
strings:
	$a0 = { b90700ba3001cd21721fb8023dba9e00cd2193b8004233c999cd21b440b93600ba0001cd21b43ecd21b8004ccd212a2e636f6d00 }


condition:
	$a0
}