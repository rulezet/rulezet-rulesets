rule Win_Trojan_Avalanche_1
{
strings:
	$a0 = { 881f3900b901432f8a1f5c0232d332c8cc20734eb541b80201bb3600cc207342b9034332d332c8cc }


condition:
	$a0
}