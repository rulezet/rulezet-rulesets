rule RansomCryptoApp_A
{
	meta:
		Description  = "Ransom.CryptoApp.sm"
		ThreatLevel  = "5"

	strings:

		$pdb0 = "CryptoApp.pdb" ascii wide
		$pdb1 = "KeepAlive.pdb" ascii wide
		$pdb2 = "SelfDestroy.pdb" ascii wide
		$pdb3 = "CoreDownloader.pdb" ascii wide

	condition:
		(3 of them) or (any of ($pdb*))
}