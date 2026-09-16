rule Win_Trojan_Mario_2
{
strings:
	$a0 = { 17beff01b9190031044646e2fabaff01b409cd21b462cd218ec3b449cd21b80158bb0200cd21 }


condition:
	$a0
}