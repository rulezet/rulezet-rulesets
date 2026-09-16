rule Win_Trojan_Vgen_72
{
strings:
	$a0 = { 81ed030133c98ec1fc26813e040281ed742cb82135cd218c867e01899e7c0133d2bf00028ec2b96f018db60001f3a4 }


condition:
	$a0
}