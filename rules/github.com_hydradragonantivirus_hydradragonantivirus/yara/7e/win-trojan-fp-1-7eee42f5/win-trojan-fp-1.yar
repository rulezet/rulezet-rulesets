rule Win_Trojan_FP_1
{
strings:
	$a0 = { c702eb0390cd20b40bcd21e2f2e99100eb0500000000009c2eff1e43012e80064701012e803e4701fa7401cf2ec606 }


condition:
	$a0
}