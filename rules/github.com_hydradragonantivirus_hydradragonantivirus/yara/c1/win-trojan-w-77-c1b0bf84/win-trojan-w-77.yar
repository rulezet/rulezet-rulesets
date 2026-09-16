rule Win_Trojan_W_77
{
strings:
	$a0 = { f603420089850a03420033c0be3c00f7bf66ad050000f7bf96ad3d504500000f857b0200008b }


condition:
	$a0
}