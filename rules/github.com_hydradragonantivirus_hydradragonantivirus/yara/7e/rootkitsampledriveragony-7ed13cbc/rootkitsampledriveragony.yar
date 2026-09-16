rule RootkitSampleDriverAgony
{
	meta:
		Description  = "Trojan.Agony.sm"
		ThreatLevel  = "5"

	strings:
		$  = "DosDevices\\agony" ascii wide
		$  = "Device\\agony" ascii wide
		$  = "VOLUME.INI" ascii wide
		$  = "ERVICES.EXE" ascii wide
		$  = "ervices.exe" ascii wide
		$  = "agony rootkit" ascii wide
		$  = "agony" ascii wide
		$  = "for exemple: agony -p process1.exe process2.exe" ascii wide
		$a = "i386\\agony.pdb" ascii wide

	condition:
		(3 of them) or $a
}