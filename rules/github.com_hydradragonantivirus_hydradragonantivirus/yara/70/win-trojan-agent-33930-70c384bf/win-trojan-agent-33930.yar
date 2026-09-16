rule Win_Trojan_Agent_33930
{
strings:
	$a0 = { 56891c240f02deeb00 }


condition:
	$a0
}