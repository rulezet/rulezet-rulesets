rule Win_Trojan_Webmoner_6
{
strings:
	$a0 = { 2f62622e7068703f262626264141414126262626763d31266964 }


condition:
	$a0
}