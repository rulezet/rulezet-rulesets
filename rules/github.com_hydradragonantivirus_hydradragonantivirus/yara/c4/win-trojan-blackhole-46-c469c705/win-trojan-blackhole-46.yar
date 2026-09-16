rule Win_Trojan_Blackhole_46
{
strings:
	$a0 = { 70726f746f747970653b7d636174636828627364626429 }


condition:
	$a0
}