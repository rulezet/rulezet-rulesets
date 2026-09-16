rule Win_Trojan_Waledac_12
{
strings:
	$a0 = { 558bec83ec588b0d032e48008d3d1e3e400003cf }


condition:
	$a0
}