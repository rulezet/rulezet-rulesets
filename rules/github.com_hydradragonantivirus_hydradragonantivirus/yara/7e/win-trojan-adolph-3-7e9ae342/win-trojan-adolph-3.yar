rule Win_Trojan_Adolph_3
{
strings:
	$a0 = { f8f9b912b8be1fd933fff5f9f8fc }


condition:
	$a0
}