rule Win_Trojan_Dauq_3
{
strings:
	$a0 = { be06015d552bee03f5565f2e8c9ecb060e1f0e07b94c00fcac2c1baae2fac3 }


condition:
	$a0
}