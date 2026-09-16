rule Win_Trojan__0071_0001_000_1
{
strings:
	$a0 = { 0300b4408d96c004cd21b440598d965c05cd2132c0e82e008d96bc04cd215a5980e1e080c905b8 }


condition:
	$a0
}