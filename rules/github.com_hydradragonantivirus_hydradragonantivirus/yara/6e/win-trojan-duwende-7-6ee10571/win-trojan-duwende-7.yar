rule Win_Trojan_Duwende_7
{
strings:
	$a0 = { 94559b97a8c39a5ba19de59aa451a6a7eb34a627acadb2fbb0acaeafb809b6b2b4b5c63eb879bfbbbefdc2bec0c1ca4e }


condition:
	$a0
}