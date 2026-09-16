rule Win_Trojan_Messanger_1
{
strings:
	$a0 = { 7efd3f0675b8b00150b017509a1f02b100ebfeeb41803e553001751ebfb2371e57bf05041e5731 }


condition:
	$a0
}