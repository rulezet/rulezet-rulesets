rule Win_Trojan_Dauq_2
{
strings:
	$a0 = { 2bee03f5565f2e8c9e680a0e1f0e07b94c00fcac341aaae2fa }


condition:
	$a0
}