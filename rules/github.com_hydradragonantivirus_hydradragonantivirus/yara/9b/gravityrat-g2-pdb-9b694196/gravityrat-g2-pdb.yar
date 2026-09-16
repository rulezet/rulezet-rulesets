rule GravityRAT_G2_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT G2"

	strings:
		$PDB1 = "e:\\Windows Work\\G2\\G2 Main Virus\\Microsoft Virus Solutions (G2 v5) (Current)\\Microsoft Virus Solutions\\obj\\Debug\\Windows Wireless 802.11.pdb"
		$PDB2 = "e:\\Windows Work\\G2\\"
        	$PDB3 = "\\G2\\G2 Main Virus\\Microsoft Virus Solutions (G2"
	condition:
		any of them
}