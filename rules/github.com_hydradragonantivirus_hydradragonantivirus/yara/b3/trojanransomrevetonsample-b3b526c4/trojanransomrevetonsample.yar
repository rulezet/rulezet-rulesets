rule TrojanRansomRevetonSample
{
	meta:
		Description  = "Trojan.Reveton.sm"
		ThreatLevel  = "5"

	strings:
		$a = "JimmMonsterNew" ascii wide
		$  = "regedit.exe" ascii wide
		$  = "rundll32.exe" ascii wide
		$  = "msconfig.lnk" ascii wide
		$  = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide
		$  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide
		$  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctfmon.exe" ascii wide
	condition:
		(3 of them) or $a
}