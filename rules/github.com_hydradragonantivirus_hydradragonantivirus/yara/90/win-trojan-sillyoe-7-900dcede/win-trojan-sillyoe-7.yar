rule Win_Trojan_SillyOE_7
{
strings:
	$a0 = { 163e034149fdfc87d2bf0301434b87c9301587db47535b4048474f414987d2fbfa87f6474f474fe2e7 }


condition:
	$a0
}