rule Win_Trojan_Blackhole_52
{
strings:
	$a0 = { 70726f746f747970653b7d63617463682862736474776264297b }


condition:
	$a0
}