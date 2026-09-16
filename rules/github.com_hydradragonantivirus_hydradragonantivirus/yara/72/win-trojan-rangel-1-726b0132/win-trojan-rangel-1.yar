rule Win_Trojan_Rangel_1
{
strings:
	$a0 = { d7005589e581ec0202bf8a291e57bf8c291e57bf8e291e57bf90291e579a3600a100833e8c2906750a833e8e29 }


condition:
	$a0
}