rule Win_Trojan_Atas_6
{
strings:
	$a0 = { 0201b0beb98e0cbe130001fe300446e2fb }


condition:
	$a0
}