rule Win_Trojan_Agent_36221
{
strings:
	$a0 = { 558bec81eca4010000578bfc6a006a006a006a006a006a00546a006a006a006a00ff15????41008be75f85c075 }


condition:
	$a0
}