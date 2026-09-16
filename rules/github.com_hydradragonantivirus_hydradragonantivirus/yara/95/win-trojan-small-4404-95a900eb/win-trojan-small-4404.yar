rule Win_Trojan_Small_4404
{
strings:
	$a0 = { 56e99000000081eb010000008d0418e9 }


condition:
	$a0
}