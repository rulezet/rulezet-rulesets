rule Win_Trojan__0841_0006_000_1
{
strings:
	$a0 = { 72300e1fb440bf32022e8b1db9320233d2cd21b80042bf32022e8b1d33d233c9cd21b440bf3202 }


condition:
	$a0
}