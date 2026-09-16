rule Win_Trojan__0071_0001_001_1
{
strings:
	$a0 = { 8d965c05cd2132c0e82e008d96bc04cd215a5980e1e080c905b80157cd213efe86bf041f5a }


condition:
	$a0
}