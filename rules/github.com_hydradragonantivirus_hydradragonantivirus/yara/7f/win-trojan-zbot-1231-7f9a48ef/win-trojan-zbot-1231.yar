rule Win_Trojan_Zbot_1231
{
strings:
	$a0 = { 31c0e801000000c331ff89e581eca00000008d9560ffffff6a }


condition:
	$a0
}