rule Win_Trojan_Trojan_122
{
strings:
	$a0 = { 012e8e1f2e8b5702b80143e80d00 }


condition:
	$a0
}