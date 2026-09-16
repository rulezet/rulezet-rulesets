rule Win_Trojan_Plovdiv_5
{
strings:
	$a0 = { 80fc11740780fc127402eb2bcd3253 }


condition:
	$a0
}