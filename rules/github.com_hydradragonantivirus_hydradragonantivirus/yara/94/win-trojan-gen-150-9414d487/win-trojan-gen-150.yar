rule Win_Trojan_Gen_150
{
strings:
	$a0 = { bf50001e57bf94001e57bf9e001e579a7c004000bf9e001e57bfb7020e579ad10758007506e824ff }


condition:
	$a0
}