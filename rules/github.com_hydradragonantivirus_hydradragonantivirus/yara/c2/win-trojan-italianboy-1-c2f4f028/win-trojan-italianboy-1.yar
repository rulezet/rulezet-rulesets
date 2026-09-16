rule Win_Trojan_ItalianBoy_1
{
strings:
	$a0 = { 4b7403e9c2009c505351521e06575655e8bb00b8023d }


condition:
	$a0
}