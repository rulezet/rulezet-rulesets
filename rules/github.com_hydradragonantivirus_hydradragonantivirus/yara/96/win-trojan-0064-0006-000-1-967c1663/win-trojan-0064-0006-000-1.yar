rule Win_Trojan__0064_0006_000_1
{
strings:
	$a0 = { b4408d96ef04cd21b440598d968b05cd2132c0e829008d96eb04cd215a5980e1e080c91fb8 }


condition:
	$a0
}