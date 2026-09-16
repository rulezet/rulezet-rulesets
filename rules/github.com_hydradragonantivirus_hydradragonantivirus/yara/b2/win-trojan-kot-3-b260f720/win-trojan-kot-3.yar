rule Win_Trojan_Kot_3
{
strings:
	$a0 = { d0bcfe7b50535152561e069c0e1f832e130402a11304b106d3e08ec033f6b995018a9c007c26881c46 }


condition:
	$a0
}