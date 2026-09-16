rule Win_Trojan_Trojan_228
{
strings:
	$a0 = { 8d96ee01cd2193b43f8d96ca01b90300cd218b86ea }


condition:
	$a0
}