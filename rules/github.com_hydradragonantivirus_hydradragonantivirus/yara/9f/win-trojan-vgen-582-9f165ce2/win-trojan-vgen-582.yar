rule Win_Trojan_VGEN_582
{
strings:
	$a0 = { ee03b430bb69698bcbcd21b930015156fc80fcff743d3c0372398cd88bd8488ed833ff803d5a752ba103002d1400 }


condition:
	$a0
}