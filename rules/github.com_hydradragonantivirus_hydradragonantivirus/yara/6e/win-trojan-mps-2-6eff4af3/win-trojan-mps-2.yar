rule Win_Trojan_MPS_2
{
strings:
	$a0 = { 0adb7441b42ccd213ada73042ad3ebf8 }


condition:
	$a0
}