rule Win_Trojan_TAL2041_1
{
strings:
	$a0 = { 04834401fdacadb106d3e08ec033dbb80402595141cd1306b8570750cbb8cea7cd1381f3cea7 }


condition:
	$a0
}