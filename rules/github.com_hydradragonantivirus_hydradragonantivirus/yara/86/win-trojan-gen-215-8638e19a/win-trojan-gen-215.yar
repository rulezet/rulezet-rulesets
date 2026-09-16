rule Win_Trojan_Gen_215
{
strings:
	$a0 = { 1352f00a0752f189eeebe253f700f9afba290f03fe0044d9e90975bb3808e9b7f827e8e11b }


condition:
	$a0
}