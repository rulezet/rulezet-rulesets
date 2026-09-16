rule Win_Trojan_Silly_45
{
strings:
	$a0 = { 394401721b89445c89545eba2e00b440cd21b80042998bcacd21b440b118cd21b43ecd211f }


condition:
	$a0
}