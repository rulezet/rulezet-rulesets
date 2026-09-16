rule Win_Trojan_Small_1420
{
strings:
	$a0 = { 6a036a006a00684a34400068453440006a00e8f1000000 }


condition:
	$a0
}