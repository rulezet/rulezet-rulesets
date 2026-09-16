rule Win_Trojan_Ascii_61_160_23_18_1
{
strings:
	$a0 = { 36312e3136302e32332e3138 }


condition:
	$a0
}