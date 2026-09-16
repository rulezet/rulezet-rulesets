rule RansomCBTLockerApp
{
	meta:
		Description  = "Ransom.CBTLocker.sm"
		ThreatLevel  = "5"

	strings:

		$s0 = "Your personal files are encrypted by CTB-Locker" ascii wide
		$s1 = "Your documents, photos, databases and other important files have been encrypted with strongest encryption and unique key,generated for this computer" ascii wide
		$s2 = "Private decryption key is stored on a secret Internet server and nobody can decrypt your files until you pay and obtain the private key." ascii wide
		$s3 = "If you see the main locker window, follow the instructions on the locker. Overwise, it's seems that you or your antivirus deleted the locker program" ascii wide

		$s6 = "keme132.DLL" ascii wide
		$s7 = "klospad.pdb" ascii wide

	condition:
		(any of ($s*)) or (3 of them)
}