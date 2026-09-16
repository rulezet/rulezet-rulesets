rule Win_Trojan_Zbot_1247
{
strings:
	$a0 = { 89ff8b442404505d55ff150047410083ec048904245b83fb00751e5089e05068 }


condition:
	$a0
}