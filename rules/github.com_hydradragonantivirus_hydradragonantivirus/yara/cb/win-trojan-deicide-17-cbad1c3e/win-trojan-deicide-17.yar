rule Win_Trojan_Deicide_17
{
strings:
	$a0 = { e800005d83ed03bf0001be????03f557b90700f3a4b8ffffcd2180fcff74 }


condition:
	$a0
}