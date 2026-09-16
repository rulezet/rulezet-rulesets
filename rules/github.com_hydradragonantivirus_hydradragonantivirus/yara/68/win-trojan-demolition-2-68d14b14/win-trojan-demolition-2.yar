rule Win_Trojan_Demolition_2
{
strings:
	$a0 = { c60106b902069dd0149c4ee2f9cef5 }


condition:
	$a0
}