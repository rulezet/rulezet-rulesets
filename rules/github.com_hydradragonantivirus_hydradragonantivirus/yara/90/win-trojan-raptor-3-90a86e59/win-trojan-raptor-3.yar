rule Win_Trojan_Raptor_3
{
strings:
	$a0 = { bf1901b97206b43fb01f2e30052e302547e2f758595f }


condition:
	$a0
}