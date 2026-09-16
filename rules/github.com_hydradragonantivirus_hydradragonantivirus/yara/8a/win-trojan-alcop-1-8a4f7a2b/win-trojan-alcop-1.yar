rule Win_Trojan_Alcop_1
{
strings:
	$a0 = { 57696e33322e20496d656c646120746865205642205669727573 }


condition:
	$a0
}