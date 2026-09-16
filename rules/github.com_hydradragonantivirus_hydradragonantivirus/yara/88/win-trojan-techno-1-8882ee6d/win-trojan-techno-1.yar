rule Win_Trojan_Techno_1
{
strings:
	$a0 = { e80e5b01d88ed8891e2600a32a00ff2e2800be0300bf00 }


condition:
	$a0
}