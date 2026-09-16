rule Win_Trojan_VS_6
{
strings:
	$a0 = { 9c5825fffe509d065633c08ec081c69c0cbff004b90f00fcf3aa56b8aaaacd21bff0045e }


condition:
	$a0
}