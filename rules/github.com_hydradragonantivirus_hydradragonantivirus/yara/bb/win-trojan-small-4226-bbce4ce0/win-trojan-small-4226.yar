rule Win_Trojan_Small_4226
{
strings:
	$a0 = { 29c9bb00????0053535f5d }


condition:
	$a0
}