rule Win_Adware_Sahat_4
{
strings:
	$a0 = { 5b534148506f7075705d[0-2]5341484167656e743d[0-20]2e657865 }


condition:
	$a0
}