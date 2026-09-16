rule Win_Trojan_Virut_402
{
strings:
	$a0 = { 9efce8140000008ad2f5f6d3f6d383e0ff8bff8af6fcfc30 }


condition:
	$a0
}