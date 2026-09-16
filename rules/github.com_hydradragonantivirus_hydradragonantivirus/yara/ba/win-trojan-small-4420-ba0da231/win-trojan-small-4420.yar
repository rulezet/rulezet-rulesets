rule Win_Trojan_Small_4420
{
strings:
	$a0 = { 68??7640008b042468600a000050e84700000068 }


condition:
	$a0
}