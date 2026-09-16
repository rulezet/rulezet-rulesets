rule Win_Trojan__1849_0004_001_1
{
strings:
	$a0 = { b8004233c933d2cd21b440b91800ba7601cd21b801575a59cd21b43ecd211f075f5e5a595b589d }


condition:
	$a0
}