rule Win_Spyware_Zbot_1280
{
strings:
	$a0 = { 5e313d????40008b3d????4000c20400 }


condition:
	$a0
}