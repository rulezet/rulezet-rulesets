rule Win_Trojan_HaryAnto_3
{
strings:
	$a0 = { bb3e0281eb2a018b0f1e5b03cb0e51b9 }


condition:
	$a0
}