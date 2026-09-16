rule RogueDownloaderLoaderAVSoftA
{
	meta:
		Description  = "Trojan.Loader.sm"
		ThreatLevel  = "5"

	strings:
		$ = "/info.php?idd=" ascii wide
		$ = "{95B8F20E-4BC6-4E22-9442-BFB69ED62879}" ascii wide
						$ = "ELEVATECREATEPROCESS" ascii wide
		$ = "srvdev.dll" ascii wide
		
	condition:
		3 of them
}