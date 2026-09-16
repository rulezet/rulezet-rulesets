rule Win_Trojan_Tiny_74
{
strings:
	$a0 = { 4b74052eff2ec40352531e0689d7b82e433805740347 }


condition:
	$a0
}