rule Win_Trojan_Gorinich_1
{
strings:
	$a0 = { 1e06b800bacd2180fcde7455b430cd213c02724db448bb3400cd21720d8ec0488ed8c70601000800eb145850 }


condition:
	$a0
}