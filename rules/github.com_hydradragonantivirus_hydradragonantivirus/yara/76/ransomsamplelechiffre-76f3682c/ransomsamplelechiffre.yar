rule RansomSampleLeChiffre
{
	meta:
		Description  = "Ransom.Win32.LeChiffre.sm"
		ThreatLevel  = "5"

	strings:
		$ = "LeChiffre" ascii wide nocase
		$ = "decrypt.my.files@gmail.com" ascii wide nocase
		$ = "http://184.107.251.146/sipvoice.php?" ascii wide nocase
		$ = "_secret_code.txt" ascii wide nocase
		$ = "_How to decrypt LeChiffre files.html" ascii wide nocase
	condition:
		2 of them
}