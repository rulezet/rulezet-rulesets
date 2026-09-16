rule Win_Trojan_Klaeren_1
{
strings:
	$a0 = { 51e800005b81ebaf03b9a50380 }


condition:
	$a0
}