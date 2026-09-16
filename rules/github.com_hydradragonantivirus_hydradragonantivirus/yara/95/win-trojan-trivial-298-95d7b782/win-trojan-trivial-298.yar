rule Win_Trojan_Trivial_298
{
strings:
	$a0 = { 2f01b44ecd21721dba9e00b8013dcd2193b440b93300ba0001cd21b43ecd21b44fcd2173e3b409 }


condition:
	$a0
}