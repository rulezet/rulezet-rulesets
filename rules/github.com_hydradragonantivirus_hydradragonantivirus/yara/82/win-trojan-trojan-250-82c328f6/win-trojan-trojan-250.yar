rule Win_Trojan_Trojan_250
{
strings:
	$a0 = { 012e8104000046464f75f6 }


condition:
	$a0
}