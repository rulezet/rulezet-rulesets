rule Win_Trojan_Zbot_1347
{
strings:
	$a0 = { 7700690067006100730074006f0070006f0065006c006100 }


condition:
	$a0
}