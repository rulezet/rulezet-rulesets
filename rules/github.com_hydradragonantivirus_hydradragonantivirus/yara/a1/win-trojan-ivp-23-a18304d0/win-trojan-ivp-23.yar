rule Win_Trojan_IVP_23
{
strings:
	$a0 = { b821008bf0bb????8bd32e812c????46464a75f6 }


condition:
	$a0
}