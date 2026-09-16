rule Win_Trojan_Agent_34321
{
strings:
	$a0 = { 64a1000000008b4004250000ffff2d000001006681384d5a75f468??????0050a3??????00eb }


condition:
	$a0
}