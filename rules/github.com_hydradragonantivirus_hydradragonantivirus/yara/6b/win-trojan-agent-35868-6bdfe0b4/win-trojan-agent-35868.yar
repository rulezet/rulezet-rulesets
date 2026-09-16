rule Win_Trojan_Agent_35868
{
strings:
	$a0 = { 4d5a[50-80]46534721 }

	$a1 = { 7461 }

	$a2 = { 470045004e00300043004900440045 }


condition:
	$a0 and $a1 and $a2
}