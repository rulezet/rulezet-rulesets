rule Win_Trojan_Psyco_1
{
strings:
	$a0 = { b440b904008d95f203cd21b8024233c98bd1cd218d95fc00b440b92403cd21b801578b8da403 }


condition:
	$a0
}