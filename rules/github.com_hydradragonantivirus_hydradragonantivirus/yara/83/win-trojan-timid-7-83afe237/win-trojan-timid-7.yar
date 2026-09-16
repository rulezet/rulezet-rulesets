rule Win_Trojan_Timid_7
{
strings:
	$a0 = { b932018b16fcff8b1e55ffb440cd2133 }


condition:
	$a0
}