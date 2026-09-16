rule Win_Trojan_Pyteconte_1
{
strings:
	$a0 = { 7a687567656c69616e6e7531 }


condition:
	$a0
}