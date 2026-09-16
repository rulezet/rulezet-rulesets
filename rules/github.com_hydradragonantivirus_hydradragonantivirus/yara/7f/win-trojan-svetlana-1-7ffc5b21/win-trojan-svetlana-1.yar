rule Win_Trojan_Svetlana_1
{
strings:
	$a0 = { 04b440e8dafd72253d5604752033c933d2b80042e8c9fd7214ba2a04b440b91800e8bcfd7207 }


condition:
	$a0
}