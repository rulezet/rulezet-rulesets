rule Win_Trojan_Stoned_55
{
strings:
	$a0 = { c08ed88ed0b8007c8be08bf0fb1e508b0e4c00890e9b7c8b0e4e00890e9d7c33ff8b1e13044b891e1304b90602 }


condition:
	$a0
}