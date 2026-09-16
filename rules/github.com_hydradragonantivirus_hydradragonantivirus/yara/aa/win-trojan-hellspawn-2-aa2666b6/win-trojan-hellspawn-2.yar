rule Win_Trojan_Hellspawn_2
{
strings:
	$a0 = { 1304b106d3e02d10008ec01f1ebe0001bf0001b9d204f2 }


condition:
	$a0
}