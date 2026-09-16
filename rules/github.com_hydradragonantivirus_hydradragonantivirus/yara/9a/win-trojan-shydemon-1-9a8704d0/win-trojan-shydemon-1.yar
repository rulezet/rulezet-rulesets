rule Win_Trojan_ShyDemon_1
{
strings:
	$a0 = { 8644078d9e3701b9e602902e31074343e2f958595bc3 }


condition:
	$a0
}