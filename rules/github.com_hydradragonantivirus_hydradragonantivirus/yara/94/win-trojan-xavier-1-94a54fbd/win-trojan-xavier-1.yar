rule Win_Trojan_Xavier_1
{
strings:
	$a0 = { 81ed030133c98ec1fc26813e040281ed742bb82135cd21899e7b018c867d0133d28ec2bf00028db60001b99401f3a4 }


condition:
	$a0
}