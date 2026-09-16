rule Win_Trojan_Taras_1
{
strings:
	$a0 = { 9700c80006008dbe00ff16576a009acc069700bfb4001e576a4f9a83089700bf2d021e57bfb4001e579a9a0497 }


condition:
	$a0
}