rule Win_Trojan_Berserker_1
{
strings:
	$a0 = { 4bf2f79546118ad533c132c480ad3d11fff79d3d11e81a00b106d2854111f7953c11f6daf7953d1180f217eb3be4bd }


condition:
	$a0
}