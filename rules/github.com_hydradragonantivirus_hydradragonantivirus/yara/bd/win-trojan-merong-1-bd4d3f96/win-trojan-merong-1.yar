rule Win_Trojan_Merong_1
{
strings:
	$a0 = { 4950484f4e45382e3528686f73743a25732c69703a257329 }


condition:
	$a0
}