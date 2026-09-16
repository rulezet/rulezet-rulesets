rule Win_Trojan_KeyKapture_2
{
strings:
	$a0 = { 488ed8c60600005a812e03002001812e1200200133 }


condition:
	$a0
}