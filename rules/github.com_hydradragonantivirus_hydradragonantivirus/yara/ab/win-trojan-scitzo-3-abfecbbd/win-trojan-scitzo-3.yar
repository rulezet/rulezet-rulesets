rule Win_Trojan_Scitzo_3
{
strings:
	$a0 = { e800005e83ee650e1fb8cdabcd213d484174679090b44abbffffcd2183eb5590b44acd21b448 }


condition:
	$a0
}