rule Win_Trojan_VGEN_503
{
strings:
	$a0 = { e80700eb75cd200000ffb430bbf103cd2181fb2923750b8bec8b6e00c3ea000000005d3c037253b448bb3c00cd2173 }


condition:
	$a0
}