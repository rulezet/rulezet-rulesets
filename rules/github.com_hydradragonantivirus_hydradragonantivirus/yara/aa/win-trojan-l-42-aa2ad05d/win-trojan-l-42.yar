rule Win_Trojan_L_42
{
strings:
	$a0 = { bacc03ec24fdb2c2eeb44ccd21e85fffb462cd215333c08ed88e1efe04813e810e434f743d93 }


condition:
	$a0
}