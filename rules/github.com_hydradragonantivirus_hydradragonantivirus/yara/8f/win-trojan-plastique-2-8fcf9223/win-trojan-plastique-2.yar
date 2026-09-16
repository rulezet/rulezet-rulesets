rule Win_Trojan_Plastique_2
{
strings:
	$a0 = { 041f240c3c0c752ee460247f3c5375 }


condition:
	$a0
}