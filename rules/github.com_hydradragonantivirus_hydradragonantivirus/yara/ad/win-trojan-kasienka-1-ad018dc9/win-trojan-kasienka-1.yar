rule Win_Trojan_Kasienka_1
{
strings:
	$a0 = { 50bf36021e579ac307e6009a9102e6008dbed4fe1657bf3a021e57ff363602bf38021e579a }


condition:
	$a0
}