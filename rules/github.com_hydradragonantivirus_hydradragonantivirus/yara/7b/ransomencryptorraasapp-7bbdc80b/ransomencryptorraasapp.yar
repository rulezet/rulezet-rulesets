rule RansomEncryptorRaaSApp
{
	meta:
		Description  = "Ransom.EncryptorRaaS.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "decryptoraveidf7.onion.to" ascii wide
		$s1 = "encryptor_raas_readme_liesmich.txt" ascii wide
		$s2 = "The files on your computer have been securely encrypted by Encryptor RaaS" ascii wide
		$s3 = "Die Dateien auf Ihrem Computer wurden von Encryptor RaaS sicher verschluesselt" ascii wide
		$s4 = "encryptor3awk6px.onion" ascii wide

	condition:
		any of ($s*)
}