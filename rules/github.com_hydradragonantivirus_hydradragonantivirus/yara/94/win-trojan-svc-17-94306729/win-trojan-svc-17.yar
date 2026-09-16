rule Win_Trojan_SVC_17
{
strings:
	$a0 = { 02b00abb007eb90200ba8000cd137205 }


condition:
	$a0
}