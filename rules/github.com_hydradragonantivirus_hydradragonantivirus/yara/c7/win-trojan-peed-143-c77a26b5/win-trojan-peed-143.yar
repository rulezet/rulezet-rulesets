rule Win_Trojan_Peed_143
{
strings:
	$a0 = { f7db87da755468b5f5fcff56e83d0000002d }


condition:
	$a0
}