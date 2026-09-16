rule Win_Trojan_WhaleMutant_5
{
strings:
	$a0 = { 83c303e2f78bcb598bd959b460eb1d56e80200 }


condition:
	$a0
}