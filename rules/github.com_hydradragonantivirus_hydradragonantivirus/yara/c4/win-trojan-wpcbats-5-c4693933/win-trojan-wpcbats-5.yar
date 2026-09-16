rule Win_Trojan_WpcBats_5
{
strings:
	$a0 = { 32058846002630470283eb044c81fc4c0174040bdb74d8 }


condition:
	$a0
}