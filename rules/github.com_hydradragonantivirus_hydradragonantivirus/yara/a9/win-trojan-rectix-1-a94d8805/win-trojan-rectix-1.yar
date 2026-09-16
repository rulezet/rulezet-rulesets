rule Win_Trojan_Rectix_1
{
strings:
	$a0 = { 558bec81ec500600005333db391d605d????c645ff010f84a0030000391d645d????0f8494030000391d845d????743868040100 }


condition:
	$a0
}