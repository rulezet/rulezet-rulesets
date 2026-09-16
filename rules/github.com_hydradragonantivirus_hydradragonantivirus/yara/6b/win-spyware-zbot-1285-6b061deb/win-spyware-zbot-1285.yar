rule Win_Spyware_Zbot_1285
{
strings:
	$a0 = { 4756f7dec3 }


condition:
	$a0
}