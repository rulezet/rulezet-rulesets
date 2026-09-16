rule TrojanWin32NecursSample
{
 	meta:
 		Description  = "Trojan.Necurs.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "some stupid error %u" ascii wide
		$ = "loading" ascii wide
		$ = "unloading" ascii wide
		$ = "exception %08x %swhen %s at %p" ascii wide
		$ = "microsoft.com" ascii wide
		$ = "facebook.com" ascii wide
		$a = "NitrGB" ascii wide
		$ = "\\Installer\\{" ascii wide
		$ = "%s%0.8X-%0.4X-%0.4X-%0.4X-%0.8X%0.4X}\\" ascii wide
		$ = "syshost32" ascii wide
		$ = "%s\\svchost.exe" ascii wide

 	condition:
 		(8 of them) or $a
}