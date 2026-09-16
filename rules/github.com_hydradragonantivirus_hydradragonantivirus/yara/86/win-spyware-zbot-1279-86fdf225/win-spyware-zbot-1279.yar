rule Win_Spyware_Zbot_1279
{
strings:
	$a0 = { 90558bec81c4 }


condition:
	$a0
}