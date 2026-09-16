rule Win_Trojan_Dutch_Tiny_3
{
strings:
	$a0 = { d1e973014e8bfead33c3abe2fa5e595b58c3e8dcff89840f02b4408d940501b90701cd219c }


condition:
	$a0
}