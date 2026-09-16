rule Win_Trojan_Creeper_5
{
strings:
	$a0 = { b8ff43cd218cd82d11008ed8803e00015a }


condition:
	$a0
}