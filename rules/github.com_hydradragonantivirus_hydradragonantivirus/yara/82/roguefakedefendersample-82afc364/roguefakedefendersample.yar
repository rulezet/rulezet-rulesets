rule RogueFakeDefenderSample
{
	meta:
		Description  = "Rogue.FakeDef.sm"
		ThreatLevel  = "5"

	strings:
		$a = "pcdfdata" 		ascii wide
		$b = "toplevel_pcdef" 	ascii wide
		
		$ = "%spld%d.exe" ascii wide
		$ = "avsrun.exe" ascii wide
		$ = "avsdel.exe" ascii wide
		
		$ = "vl.bin" ascii wide
		$ = "reginfo.bin" ascii wide
		
		$ = "%s%s.lnk" ascii wide
		$ = "%sRemove %s.lnk" ascii wide
		$ = "Uninstaller application" ascii wide
		$ = "%s%s Help and Support.lnk" ascii wide
		
		$ = "pavsdata" ascii wide
		$ = "avsmainwnd" ascii wide
		$ = "avsdsvc" ascii wide
		$ = "ovcf" ascii wide
		
		$ = "Global\\avsinst" ascii wide
		$ = "Global\\avscfglock" ascii wide
		$ = "\\loc\\reg\\conn\\activate" ascii wide
		$ = "\\forms\\alerts\\vulner" ascii wide
		$ = "\\forms\\alerts\\hack" ascii wide
		
		$ = "Software\\Classes\\.exe" ascii wide
		
		$ = "%s was infected with %s and has been successfully repaired" ascii wide
		$ = "Attack %s from remote host %d.%d.%d.%d has been successfully blocked" ascii wide
			
		$ = "http://%s/api/ping?stage=1&uid=%S&id=%d&subid=%d&os=%d&avf=%d" ascii wide
		$ = "http://%s/api/ping?stage=2&uid=%S&success=%d" ascii wide
		$ = "http://%s/api/ping?stage=3&uid=%S" ascii wide
		$ = "http://%s/content/scc" ascii wide
		$ = "http://%s/postload2/?uid=%S" ascii wide
		$ = "http://%S/api/test" ascii wide
		$ = "http://%s/load/?uid=%S" ascii wide
		$ = "http://%s/html/viruslist/?uid=%S" ascii wide
		$ = "https://%s/billing/key/?uid=%S" ascii wide
		$ = "https://%s/html/billing/?uid=%S" ascii wide

	condition:
		3 of them
}