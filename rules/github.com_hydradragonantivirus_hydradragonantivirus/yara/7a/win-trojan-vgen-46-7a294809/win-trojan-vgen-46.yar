rule Win_Trojan_VGEN_46
{
strings:
	$a0 = { 8ed8a120008b1e22008edb89c3b9ea0003d98b4700508b470289c333c08ed858a32000891e2200fbb8004ccd21 }


condition:
	$a0
}