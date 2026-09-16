rule Win_Trojan_Dutch_Tiny_7
{
strings:
	$a0 = { e973014e8bfead33c3abe2fa5e595b58c3e8dcff89844002b4408d940501b93801cd219c }


condition:
	$a0
}