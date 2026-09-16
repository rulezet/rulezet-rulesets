rule Win_Trojan_MG_3
{
strings:
	$a0 = { 3e0600b0ea49f2ae26c43d83efdfea }


condition:
	$a0
}