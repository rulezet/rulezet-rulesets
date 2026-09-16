rule Win_Trojan_Vodka_1
{
strings:
	$a0 = { 5d83ed031eb461cd213c207453fab800008ed8832e1304018cc0488ed8832e030040832e120040ff361200ff36 }


condition:
	$a0
}