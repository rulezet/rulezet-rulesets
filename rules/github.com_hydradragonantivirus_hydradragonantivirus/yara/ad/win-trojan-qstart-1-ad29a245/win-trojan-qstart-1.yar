rule Win_Trojan_Qstart_1
{
strings:
	$a0 = { b9ff0031c088e0e670eb008a0743fec4e671e2f1b44ccd21 }


condition:
	$a0
}