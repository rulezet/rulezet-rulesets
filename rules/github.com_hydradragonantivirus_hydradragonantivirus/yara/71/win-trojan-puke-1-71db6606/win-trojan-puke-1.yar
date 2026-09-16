rule Win_Trojan_Puke_1
{
strings:
	$a0 = { 9999750333c0cf3d004b7503e818002eff2e8b02b80242 }


condition:
	$a0
}