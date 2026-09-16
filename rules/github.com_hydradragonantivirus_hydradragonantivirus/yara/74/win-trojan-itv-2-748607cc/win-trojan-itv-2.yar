rule Win_Trojan_Itv_2
{
strings:
	$a0 = { 80f2aeb90400acae75efe2fa0789bef4028dbe2703 }


condition:
	$a0
}