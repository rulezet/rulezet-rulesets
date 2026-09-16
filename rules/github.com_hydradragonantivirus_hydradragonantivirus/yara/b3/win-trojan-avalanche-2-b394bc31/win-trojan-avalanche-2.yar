rule Win_Trojan_Avalanche_2
{
strings:
	$a0 = { 0a0000bb1e02eb0790ea2e80370043e2f9 }


condition:
	$a0
}