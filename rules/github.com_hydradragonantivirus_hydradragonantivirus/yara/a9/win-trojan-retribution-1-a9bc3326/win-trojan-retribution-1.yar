rule Win_Trojan_Retribution_1
{
strings:
	$a0 = { 01ba6e07cde17303eb3190b440b91200ba4707cde1b80042b900008bd1cde1b4408b0e3601 }


condition:
	$a0
}