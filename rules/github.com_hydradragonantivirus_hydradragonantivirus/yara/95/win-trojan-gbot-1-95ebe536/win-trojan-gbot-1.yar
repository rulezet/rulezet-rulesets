rule Win_Trojan_Gbot_1
{
strings:
	$a0 = { 558bec81eca4010000578bfc6a006a006a006a006a006a00546a006a006a006a002eff15????41008be75f85c0752c6a00506a03ff15????41003b042a74??b8 }


condition:
	$a0
}