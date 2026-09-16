rule Win_Trojan_Haxspy_4
{
strings:
	$a0 = { 68400601006a006a006a1568080601006a00ff7508e831000000 }


condition:
	$a0
}