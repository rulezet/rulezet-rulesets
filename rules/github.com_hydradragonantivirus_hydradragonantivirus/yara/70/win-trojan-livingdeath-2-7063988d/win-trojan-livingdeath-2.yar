rule Win_Trojan_LivingDeath_2
{
strings:
	$a0 = { 0800bb5d1003dd1e065333c01e501fbb5192891efe0443891efc04cd08391efe045a7505a1fc04eb554a521f8b1e }


condition:
	$a0
}