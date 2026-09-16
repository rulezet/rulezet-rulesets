rule Win_Trojan_MemLapse_5
{
strings:
	$a0 = { 2e8b2e01018db61d01b95d018a0432861c01880446e2f5eb01 }


condition:
	$a0
}