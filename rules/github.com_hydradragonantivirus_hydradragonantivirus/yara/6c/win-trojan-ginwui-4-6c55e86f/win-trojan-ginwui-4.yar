rule Win_Trojan_Ginwui_4
{
strings:
	$a0 = { 6a006a006a006a006a008d442418506a006a026a1068ff010f0068ac36400068ac36400056e840ffffff }


condition:
	$a0
}