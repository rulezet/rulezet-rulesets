rule Win_Trojan_Yelet_1
{
strings:
	$a0 = { 012e8a042e328603013c90740a9090902efe860301 }


condition:
	$a0
}