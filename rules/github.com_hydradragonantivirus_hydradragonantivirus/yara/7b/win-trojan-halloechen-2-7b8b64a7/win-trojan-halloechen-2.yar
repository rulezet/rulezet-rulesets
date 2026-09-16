rule Win_Trojan_Halloechen_2
{
strings:
	$a0 = { 1e03004303c38ed8803e00005a75 }


condition:
	$a0
}