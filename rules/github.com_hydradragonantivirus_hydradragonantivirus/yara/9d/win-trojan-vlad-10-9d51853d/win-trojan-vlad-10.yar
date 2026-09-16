rule Win_Trojan_VLAD_10
{
strings:
	$a0 = { 01e8f400b80263cd213bc374388cd8488ed833ff803d5a752c836d032290836d1222908e45120e1ffcb90401be00 }


condition:
	$a0
}