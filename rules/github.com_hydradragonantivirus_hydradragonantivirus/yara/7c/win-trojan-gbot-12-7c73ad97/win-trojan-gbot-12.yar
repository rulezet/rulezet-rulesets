rule Win_Trojan_Gbot_12
{
strings:
	$a0 = { 558bec81eca4010000578bfc6a006a006a006a006a006a006a006a00f3ff15????41008be75f480faf013c7c3675256a }


condition:
	$a0
}