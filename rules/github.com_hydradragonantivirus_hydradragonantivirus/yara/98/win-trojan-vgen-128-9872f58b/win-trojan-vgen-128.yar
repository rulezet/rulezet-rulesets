rule Win_Trojan_Vgen_128
{
strings:
	$a0 = { ba0001cdfe0653b80102bb007eba8000b90100cd13cb3dc2c37503f7d0cf80fc02740580fc0375 }


condition:
	$a0
}