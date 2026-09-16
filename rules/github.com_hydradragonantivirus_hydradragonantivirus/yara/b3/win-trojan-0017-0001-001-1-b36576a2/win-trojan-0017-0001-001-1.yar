rule Win_Trojan__0017_0001_001_1
{
strings:
	$a0 = { b3005a8b4e27b440cd21e8c2045a59b440cd21e81902b440cd21b8004233c999cd218bd6b90300 }


condition:
	$a0
}