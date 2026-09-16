rule Win_Trojan_CorporateLife_5
{
strings:
	$a0 = { 9090900e4e461f46bf190746bb3e01fb4e90fb803749904e4390904f75f54646909046fbfb464e4e904efbfb }


condition:
	$a0
}