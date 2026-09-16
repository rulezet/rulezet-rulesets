rule Win_Trojan_Srp_2
{
strings:
	$a0 = { 018b5e0a8b4706508b5e0a8b07508b5e06b90600ff374343e2fa5f5e5a595b58071fcd219c }


condition:
	$a0
}