rule Win_Trojan__1707_0001_000_1
{
strings:
	$a0 = { b97306908dbefb078db60801e86600b440cd218f86fb01b80042e82b008d96f601b90500b440cd }


condition:
	$a0
}