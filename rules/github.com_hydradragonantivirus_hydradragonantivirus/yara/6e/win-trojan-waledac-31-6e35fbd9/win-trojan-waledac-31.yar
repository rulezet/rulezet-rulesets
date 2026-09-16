rule Win_Trojan_Waledac_31
{
strings:
	$a0 = { 558bec21c08d46f3b9482400004e2bf951496814744100ff }


condition:
	$a0
}