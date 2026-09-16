rule Win_Trojan_ZeusGameover_1
{
strings:
	$a0 = { 5c6475726b615c707369687573686b612e706462 }


condition:
	$a0
}