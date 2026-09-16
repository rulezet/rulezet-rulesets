rule Win_Trojan_Hdzz_1
{
strings:
	$a0 = { 33c08ec026813ef603b6077503eb669026c706f603b607 }


condition:
	$a0
}