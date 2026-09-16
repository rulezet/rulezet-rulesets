rule Win_Trojan_WhaleMutant_6
{
strings:
	$a0 = { 4083c303e2f78cc0588bd859b450eb1e56fde80200 }


condition:
	$a0
}