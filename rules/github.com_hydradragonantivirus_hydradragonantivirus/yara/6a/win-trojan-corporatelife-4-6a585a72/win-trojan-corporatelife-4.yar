rule Win_Trojan_CorporateLife_4
{
strings:
	$a0 = { fb06904e900e461f46fb90b815079090bb3e014e9046908037d090904e4346464875f4464646fbfb4e90fb4e904e }


condition:
	$a0
}