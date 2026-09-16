rule Win_Trojan_Beethoven_1
{
strings:
	$a0 = { ba1008cd2139c87404b004eb26b8004289fa89f1cd217304b006eb17b44031d2b9c00bcd21 }


condition:
	$a0
}