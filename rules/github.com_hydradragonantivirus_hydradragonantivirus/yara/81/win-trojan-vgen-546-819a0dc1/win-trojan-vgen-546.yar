rule Win_Trojan_VGEN_546
{
strings:
	$a0 = { 2e002e803e3606037404b04febce5a1f9cb41acd219d2ec6063806005f5e071f5a595b58e950ff }


condition:
	$a0
}