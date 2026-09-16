rule Win_Trojan_ABC_2
{
strings:
	$a0 = { 17433d48097703e90afe33d29c1e528cc08ed833c0cf }


condition:
	$a0
}