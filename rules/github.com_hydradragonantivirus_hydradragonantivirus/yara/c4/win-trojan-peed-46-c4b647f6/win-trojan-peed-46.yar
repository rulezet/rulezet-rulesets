rule Win_Trojan_Peed_46
{
strings:
	$a0 = { 89c189e58d651c5fc1ef0589ec05624503004f2d6145 }


condition:
	$a0
}