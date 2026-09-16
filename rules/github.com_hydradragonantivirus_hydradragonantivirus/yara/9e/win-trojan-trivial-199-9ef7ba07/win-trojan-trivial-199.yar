rule Win_Trojan_Trivial_199
{
strings:
	$a0 = { 01b44ecd2181c27dffb8023dcd21938ad0b442cd21b440b125b601cd21c3 }


condition:
	$a0
}