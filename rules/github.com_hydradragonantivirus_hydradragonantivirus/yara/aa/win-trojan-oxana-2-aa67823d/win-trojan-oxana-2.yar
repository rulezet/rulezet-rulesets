rule Win_Trojan_Oxana_2
{
strings:
	$a0 = { 35cd218cc88ed82b069e03a39e038cc03d00007559b8 }


condition:
	$a0
}