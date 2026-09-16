rule Win_Trojan_Trivial_308
{
strings:
	$a0 = { 0301b90000b44ecd210ac07518b002ba9e00b43dcd2193b93500ba0000b440cd21b43ecd21b44cb000cd21 }


condition:
	$a0
}