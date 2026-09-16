rule Win_Trojan_Tiny_48
{
strings:
	$a0 = { 0201b960008ec133ff8db70001b1a3fcf3a41f1ebe84 }


condition:
	$a0
}