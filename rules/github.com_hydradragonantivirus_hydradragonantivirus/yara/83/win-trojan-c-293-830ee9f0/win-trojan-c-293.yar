rule Win_Trojan_C_293
{
strings:
	$a0 = { 633a5c6174746163686d656e742e766273 }

	$a1 = { 687474703a2f2f6d656d626572732e747269706f642e }


condition:
	$a0 and $a1
}