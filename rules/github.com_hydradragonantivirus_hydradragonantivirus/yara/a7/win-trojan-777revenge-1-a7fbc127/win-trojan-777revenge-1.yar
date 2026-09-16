rule Win_Trojan_777Revenge_1
{
strings:
	$a0 = { ff33c9cd2183f9067243b8560250 }


condition:
	$a0
}