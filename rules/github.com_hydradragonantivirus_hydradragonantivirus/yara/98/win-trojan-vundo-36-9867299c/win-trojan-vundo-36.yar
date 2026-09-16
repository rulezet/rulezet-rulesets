rule Win_Trojan_Vundo_36
{
strings:
	$a0 = { 60e8561f00003e9fecb54abbd8311625 }


condition:
	$a0
}