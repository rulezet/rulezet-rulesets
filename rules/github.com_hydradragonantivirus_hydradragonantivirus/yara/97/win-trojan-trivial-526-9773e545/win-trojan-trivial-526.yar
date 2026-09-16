rule Win_Trojan_Trivial_526
{
strings:
	$a0 = { b44ecd21ba9e00b43ccd21ba0001b740b11c93cd212a2e }


condition:
	$a0
}