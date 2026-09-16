rule Win_Trojan_Frz_2
{
strings:
	$a0 = { e800005e81ee75000e1f8bde81c3a900b9d107eb10908a279090909090882743e2f4eb13902e83bc }


condition:
	$a0
}