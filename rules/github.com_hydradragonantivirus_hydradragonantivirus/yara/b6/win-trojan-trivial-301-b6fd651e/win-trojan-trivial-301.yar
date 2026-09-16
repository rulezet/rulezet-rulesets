rule Win_Trojan_Trivial_301
{
strings:
	$a0 = { 2d01b92700cd21721fb42fcd2189de8d541eb8023dcd2193b93300ba0001b440cd21b44fcd2173e1cd202a2e434f4d00 }


condition:
	$a0
}