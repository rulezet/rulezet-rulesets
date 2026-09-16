rule Win_Trojan_Goma_15
{
strings:
	$a0 = { 53542e4d5300b44fcd217226b8023dba9e00cd218bd8b98701ba0001b440cd21b43ecd21ebe043 }


condition:
	$a0
}