rule Win_Trojan_Rukap_53
{
strings:
	$a0 = { eab30a7e6c2af0af801dad673a17fa2aad32821a9c93bd6e63ae0721730100b8dea67b63e2172785ef939a7337aa95ea6506609d1dd0ebe0639aa0475493efc60d60a7e57a239bbb }


condition:
	$a0
}