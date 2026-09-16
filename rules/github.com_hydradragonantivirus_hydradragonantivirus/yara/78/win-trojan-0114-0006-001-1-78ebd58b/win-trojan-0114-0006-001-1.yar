rule Win_Trojan__0114_0006_001_1
{
strings:
	$a0 = { 21b44059ba3604cd2132c0e83100ba1704cd215a5980e1e080c901b80157cd211f5a59e80f00b4 }


condition:
	$a0
}