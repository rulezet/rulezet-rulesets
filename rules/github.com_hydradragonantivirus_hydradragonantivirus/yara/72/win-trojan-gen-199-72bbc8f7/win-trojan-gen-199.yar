rule Win_Trojan_Gen_199
{
strings:
	$a0 = { 64008ad08b8658ed05900f8bf88895580083be58ed0b75da8dbefefc1657bf17050e579a9d06 }


condition:
	$a0
}