rule Win_Spyware_Zbot_1288
{
strings:
	$a0 = { 4eff308bdf4f8bd1c3 }


condition:
	$a0
}