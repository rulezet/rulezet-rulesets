rule Win_Trojan_BlackMonday_2
{
strings:
	$a0 = { 010181c605018b048b5c02a30001 }


condition:
	$a0
}