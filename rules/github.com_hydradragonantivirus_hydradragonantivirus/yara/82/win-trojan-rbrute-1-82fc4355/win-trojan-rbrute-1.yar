rule Win_Trojan_Rbrute_1
{
strings:
	$a0 = { 534b4b32394d584144 }


condition:
	$a0
}