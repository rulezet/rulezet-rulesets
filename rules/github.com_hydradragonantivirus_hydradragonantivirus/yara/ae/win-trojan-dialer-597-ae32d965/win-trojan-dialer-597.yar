rule Win_Trojan_Dialer_597
{
strings:
	$a0 = { 687474703a2f2f36392e39332e3134322e3135342f636f6e74656e7400 }

	$a1 = { 303034333832303839 }


condition:
	$a0 and $a1
}