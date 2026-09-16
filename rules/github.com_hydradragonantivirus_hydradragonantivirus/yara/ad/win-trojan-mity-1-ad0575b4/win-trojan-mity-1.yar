rule Win_Trojan_Mity_1
{
strings:
	$a0 = { 022e8b4c06412e8b5404bb409f8ec3bb0001cd13061f33c08ec0bf1300d1e7d1e7268b1d89 }


condition:
	$a0
}