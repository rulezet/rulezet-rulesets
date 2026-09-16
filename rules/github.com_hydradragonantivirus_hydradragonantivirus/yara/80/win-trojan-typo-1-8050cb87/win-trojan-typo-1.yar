rule Win_Trojan_Typo_1
{
strings:
	$a0 = { 5351521e06560e1fe800005e83ee24ff }


condition:
	$a0
}