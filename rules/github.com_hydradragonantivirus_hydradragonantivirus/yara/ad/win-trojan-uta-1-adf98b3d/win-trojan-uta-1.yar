rule Win_Trojan_Uta_1
{
strings:
	$a0 = { a39701ba0001b97f02b4409c2eff1e8c012bc98bd1b800429c2eff1e8c018d169601b90300 }


condition:
	$a0
}