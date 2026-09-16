rule Win_Trojan_Mirror_3
{
strings:
	$a0 = { 26a3b90126891ebb01c7068400db }


condition:
	$a0
}