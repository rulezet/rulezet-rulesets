rule Win_Adware_FunWebProducts_3
{
strings:
	$a0 = { 536f6674776172655c46756e205765622050726f6475637473 }


condition:
	$a0
}