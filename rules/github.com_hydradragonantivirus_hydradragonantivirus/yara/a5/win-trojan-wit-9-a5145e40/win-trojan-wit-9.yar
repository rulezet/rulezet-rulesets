rule Win_Trojan_Wit_9
{
strings:
	$a0 = { eda1ef02a3f102a1f302a316038a2627038b16f1020316160381c20001cd2183c21e891618038b }


condition:
	$a0
}