rule Win_Trojan_Peed_215
{
strings:
	$a0 = { 7304ffd440c3b9c05f010068ae??3d008b34245881c65242030089f25266ad69 }


condition:
	$a0
}