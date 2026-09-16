rule Win_Trojan__0224_0008_000_1
{
strings:
	$a0 = { c353ffd65b8f060f00b440b94f02ba4f02cd2133c9b8004233d2cd21baa304b44059cd21b80157 }


condition:
	$a0
}