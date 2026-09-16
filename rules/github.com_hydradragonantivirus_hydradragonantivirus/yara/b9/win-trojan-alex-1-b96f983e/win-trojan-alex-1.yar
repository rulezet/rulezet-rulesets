rule Win_Trojan_Alex_1
{
strings:
	$a0 = { f48b74fe81ee04011e06508b846c02a300018b846e02a3 }


condition:
	$a0
}