rule Win_Trojan_Diamond_5
{
strings:
	$a0 = { 8b55022bd13bd0723cfa26294d03895502 }


condition:
	$a0
}