rule Win_Trojan_268_1
{
strings:
	$a0 = { 8ec10650be00015631ffb90b01f3a4bd }


condition:
	$a0
}