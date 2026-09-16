rule Win_Trojan_Tsunami_3
{
strings:
	$a0 = { fbf805e9ba00a0612b5f002199e419e9dc66986610af61ab75fb2b5f012175f62b5f801f75f52b }


condition:
	$a0
}