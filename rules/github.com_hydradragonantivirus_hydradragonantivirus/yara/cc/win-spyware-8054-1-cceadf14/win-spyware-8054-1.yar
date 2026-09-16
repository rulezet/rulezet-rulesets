rule Win_Spyware_8054_1
{
strings:
	$a0 = { 68ff6424f0685858585890ffd4508b40 }


condition:
	$a0
}