rule Win_Trojan_Xpaj_2
{
strings:
	$a0 = { 8d4decc7012e657865c741042e646c6cc741082e736372c7410c2e737973c74110000000008b550c }


condition:
	$a0
}