rule Win_Trojan_DM_10
{
strings:
	$a0 = { b9c100f3a5061fbe84008bdebf7801a5 }


condition:
	$a0
}