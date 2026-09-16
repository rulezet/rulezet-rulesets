rule Win_Trojan_Comasp_1
{
strings:
	$a0 = { d631db8ec3bb8400268b0f890c4646 }


condition:
	$a0
}