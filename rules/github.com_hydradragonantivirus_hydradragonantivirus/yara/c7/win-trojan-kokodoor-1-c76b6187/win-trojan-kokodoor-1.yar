rule Win_Trojan_Kokodoor_1
{
strings:
	$a0 = { 4100025083024b6c69656e74655f54726f6a616e000100000000ffcc31001086a4066081e3bb48a8 }


condition:
	$a0
}