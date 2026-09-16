rule Win_Trojan_Blackhole_48
{
strings:
	$a0 = { 2270726f222b22746f222b227479706522293b7d63617463682876297b65763d }


condition:
	$a0
}