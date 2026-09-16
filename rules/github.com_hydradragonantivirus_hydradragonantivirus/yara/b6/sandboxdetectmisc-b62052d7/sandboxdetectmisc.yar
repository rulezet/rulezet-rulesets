rule SandboxDetectMisc
{
	meta:
		Description = "Risk.SBDtc.sm"
		ThreatLevel = "3"

	strings:
		$sbxie1 = "sbiedll" nocase ascii wide

		$prodid1 = "55274-640-2673064-23950" ascii wide
		$prodid2 = "76487-644-3177037-23510" ascii wide
		$prodid3 = "76487-337-8429955-22614" ascii wide

		$proc1 = "joeboxserver" ascii wide
		$proc2 = "joeboxcontrol" ascii wide
	condition:
		any of them
}