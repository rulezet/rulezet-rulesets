rule Win_Trojan__0114_0006_002_1
{
strings:
	$a0 = { 3604be0600e8a80051b90300b440ba1a04cd21b44059ba3604cd2132c0e83100ba1704cd215a59 }


condition:
	$a0
}