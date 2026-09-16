rule Win_Trojan__0638_0003_000_1
{
strings:
	$a0 = { c9cd21250f000bc07409b910002bc8b440cd21b802429933c9cd21b104d3e8b10cd3e203d02b16 }


condition:
	$a0
}