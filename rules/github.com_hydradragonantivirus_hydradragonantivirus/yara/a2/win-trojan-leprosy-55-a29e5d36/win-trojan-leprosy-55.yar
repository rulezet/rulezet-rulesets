rule Win_Trojan_Leprosy_55
{
strings:
	$a0 = { 8b16??01b92301[0-1]2e311483c602[0-3]e2f5c3 }


condition:
	$a0
}