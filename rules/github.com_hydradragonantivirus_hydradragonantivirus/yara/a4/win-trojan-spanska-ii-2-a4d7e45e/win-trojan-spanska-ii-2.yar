rule Win_Trojan_Spanska_II_2
{
strings:
	$a0 = { 368307142d33018be8c390902bdb0bdc4be800004b36812f3701368b2f3681074601c390e8 }


condition:
	$a0
}