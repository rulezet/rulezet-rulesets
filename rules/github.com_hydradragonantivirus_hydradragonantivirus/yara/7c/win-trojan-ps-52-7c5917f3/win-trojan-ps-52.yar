rule Win_Trojan_PS_52
{
strings:
	$a0 = { e800005e0e1f81ee????8bfe83e7??8bc7b104d3e88cc903c150b8????50b90000fcf3a4cb }


condition:
	$a0
}