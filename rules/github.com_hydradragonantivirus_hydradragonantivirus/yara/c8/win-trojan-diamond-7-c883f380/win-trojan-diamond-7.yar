rule Win_Trojan_Diamond_7
{
strings:
	$a0 = { c233ffb921008b55022bd13bd0723a26294d038955 }


condition:
	$a0
}