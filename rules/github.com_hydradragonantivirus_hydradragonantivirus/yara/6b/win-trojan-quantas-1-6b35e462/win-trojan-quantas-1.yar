rule Win_Trojan_Quantas_1
{
strings:
	$a0 = { 444acd21bb5a4d3d4a4474618cc0488ed8381d7558883d836d033a836d123a8b45128ed8408ec0881dc7450108 }


condition:
	$a0
}