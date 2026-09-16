rule Win_Trojan_Trojan_229
{
strings:
	$a0 = { fcb8e70091812c1d3aa7e2f9053b1d6d13934a4c1dcf2358d5724dc5f5073ebb18704eae6dc6f582ab12a06820 }


condition:
	$a0
}