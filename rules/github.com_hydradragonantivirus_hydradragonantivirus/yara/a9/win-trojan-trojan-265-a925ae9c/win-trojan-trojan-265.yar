rule Win_Trojan_Trojan_265
{
strings:
	$a0 = { 742e3c35740b3c397424ebeee8a101721d }


condition:
	$a0
}