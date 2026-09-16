rule Win_Trojan_VGEN_713
{
strings:
	$a0 = { e800005d81ed09011e068d964f02b41acd213ec686320200e82400071fba8000b41acd218db60301bf000157a5a4e801 }


condition:
	$a0
}