rule Win_Trojan_Whale_15
{
strings:
	$a0 = { ebf7582d9c2393b92ede8af1abfdf617 }


condition:
	$a0
}