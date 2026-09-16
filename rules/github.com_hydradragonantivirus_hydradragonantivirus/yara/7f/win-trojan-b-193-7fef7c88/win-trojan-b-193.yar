rule Win_Trojan_B_193
{
strings:
	$a0 = { 5c506f6c69636965735c4578706c6f7265725c52756e5c }

	$a1 = { 5c45535430323030392e657865 }


condition:
	$a0 and $a1
}