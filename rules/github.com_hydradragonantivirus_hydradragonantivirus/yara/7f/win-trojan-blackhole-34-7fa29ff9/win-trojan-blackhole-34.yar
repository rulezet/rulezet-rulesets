rule Win_Trojan_Blackhole_34
{
strings:
	$a0 = { 70726f746f747970657d636174636828717171297b }


condition:
	$a0
}