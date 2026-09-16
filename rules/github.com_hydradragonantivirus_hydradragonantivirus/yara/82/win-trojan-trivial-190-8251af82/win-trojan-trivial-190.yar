rule Win_Trojan_Trivial_190
{
strings:
	$a0 = { 2001b44ecd21ba9e00b8013dcd218bd8b440b92400ba0001cd21b43ecd21cb2a2e434f }


condition:
	$a0
}