rule Win_Trojan_Daemaen_1
{
strings:
	$a0 = { 02cea7fa33c08ed0bc007cfb8ed8b90427ba00015251e821007419be1204834401fdacadb106d3e08ec033dbb80402 }


condition:
	$a0
}