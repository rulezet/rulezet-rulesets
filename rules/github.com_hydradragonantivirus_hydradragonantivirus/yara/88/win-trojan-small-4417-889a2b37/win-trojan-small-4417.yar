rule Win_Trojan_Small_4417
{
strings:
	$a0 = { 81c8262f4200505068ccf61af1e8 }


condition:
	$a0
}