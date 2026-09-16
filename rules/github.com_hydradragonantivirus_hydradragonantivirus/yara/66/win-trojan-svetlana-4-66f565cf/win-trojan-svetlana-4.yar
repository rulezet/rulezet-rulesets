rule Win_Trojan_Svetlana_4
{
strings:
	$a0 = { b440e8c2fd72253d7e12752033c933d2b80042e8b1fd7214ba5212b440b91800e8a4fd7207 }


condition:
	$a0
}