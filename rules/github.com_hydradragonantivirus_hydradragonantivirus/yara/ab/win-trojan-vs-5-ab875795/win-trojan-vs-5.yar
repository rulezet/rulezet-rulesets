rule Win_Trojan_VS_5
{
strings:
	$a0 = { 9c5825fffe509d065633c08ec081c6860bbff004b90f00fcf3aa56b8aaaacd21bff0045e }


condition:
	$a0
}