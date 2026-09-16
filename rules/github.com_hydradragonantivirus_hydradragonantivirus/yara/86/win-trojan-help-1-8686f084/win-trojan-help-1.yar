rule Win_Trojan_Help_1
{
strings:
	$a0 = { 04001800456e756d57696e646f77732860ccc3272c4c75636b792900 }


condition:
	$a0
}