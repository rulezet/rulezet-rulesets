rule Win_Trojan_W_345
{
strings:
	$a0 = { 570f014c24fe5f83c718dd07fc66ab66afb4ee89071e06cc }


condition:
	$a0
}