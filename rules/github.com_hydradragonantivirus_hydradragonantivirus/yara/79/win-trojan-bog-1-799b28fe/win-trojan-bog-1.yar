rule Win_Trojan_Bog_1
{
strings:
	$a0 = { f0ac3c2175eb5681ee800183fe785e77df33c98bd683c27eb80042cd21b9e9008bd5b440cd21c3 }


condition:
	$a0
}