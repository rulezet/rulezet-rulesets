rule Win_Trojan_V_9
{
strings:
	$a0 = { 565f2e8b0e1c0181c14304fcac2e32061c01aae2f7eb03 }


condition:
	$a0
}