rule Win_Trojan_VGEN_391
{
strings:
	$a0 = { 30ba5249b90002cd218bec8b6efa81ed0c000bd2750c8bf533ffb929022ef3a674378cd8488ed833ff803d5a75 }


condition:
	$a0
}