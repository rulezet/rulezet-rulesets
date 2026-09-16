rule Win_Trojan_Kai_1
{
strings:
	$a0 = { 0c0189852802b440b92d0190ba030103d7cd217229b8004233c933d2cd21721eb440b90300ba27 }


condition:
	$a0
}