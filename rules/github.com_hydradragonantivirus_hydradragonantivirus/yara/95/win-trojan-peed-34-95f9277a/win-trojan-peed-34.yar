rule Win_Trojan_Peed_34
{
strings:
	$a0 = { 89e58d651c5fc1ef0589ec0562450300 }


condition:
	$a0
}