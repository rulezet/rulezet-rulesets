rule Win_Spyware_Zbot_1290
{
strings:
	$a0 = { 5746c3 }


condition:
	$a0
}