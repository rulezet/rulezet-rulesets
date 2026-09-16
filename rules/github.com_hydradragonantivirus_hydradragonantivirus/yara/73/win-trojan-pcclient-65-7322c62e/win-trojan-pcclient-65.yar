rule Win_Trojan_PcClient_65
{
strings:
	$a0 = { 8b55e8b874444000e8bde4ffffb854324000e84ffbffff }


condition:
	$a0
}