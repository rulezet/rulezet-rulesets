rule TrojanSirefefZerroAccessPlayloadModule
{
	meta:
		Description  = "Trojan.Sirefef.sm"
		ThreatLevel  = "5"

	strings:
		$ = "U\\80000032.@" ascii wide
		$ = "\\\\.\\globalroot\\systemroot\\system32\\mswsock.dll" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.AcceptEx" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.GetAcceptExSockaddrs" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.NSPStartup" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.TransmitFile" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.getnetbyname" ascii wide
		$ = "\\\\?\\globalroot\\systemroot\\system32\\mswsock.inet_network" ascii wide
		$ = "%sU\\%08x.@" ascii wide
		$ = "\\??\\%s@" ascii wide
		$ = "\\??\\%sU" ascii wide
		$ = "\\registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters" ascii wide
		$ = "\\KnownDlls\\mswsock.dll" ascii wide
		$ = "\\systemroot\\assembly" ascii wide
		$ = "GAC_MSIL" ascii wide
		$ = "GAC" ascii wide
		$ = "????????.@" ascii wide
		$ = "%08x.@" ascii wide
		$ = "%08x.$" ascii wide
		$ = "%08x.~" ascii wide
		
		$ = "\\systemroot\\assembly\\GAC\\Desktop.ini" ascii wide

	condition:
		(5 of them)
}