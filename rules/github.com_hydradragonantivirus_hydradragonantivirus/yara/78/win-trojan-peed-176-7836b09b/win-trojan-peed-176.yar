rule Win_Trojan_Peed_176
{
strings:
	$a0 = { eb0cf7db29dff7db01de89c3eb41e806000000f7da291424c329d287d15a8d1d49b5400029d2528b3b89e3535252ffd7 }


condition:
	$a0
}