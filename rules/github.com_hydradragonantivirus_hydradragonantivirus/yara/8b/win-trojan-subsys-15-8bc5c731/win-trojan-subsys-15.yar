rule Win_Trojan_Subsys_15
{
strings:
	$a0 = { 3321d89a1b2241b709dd642a88ac91eaa4d915d264e7b7b6c065e7242225a024faee5106cc649bcf5d930e2c745fd1cb }


condition:
	$a0
}