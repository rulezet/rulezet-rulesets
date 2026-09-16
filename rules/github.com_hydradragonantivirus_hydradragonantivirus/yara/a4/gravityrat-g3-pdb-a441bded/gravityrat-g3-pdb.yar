rule GravityRAT_G3_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT G3"

	strings:
		$PDB1 = "F:\\Projects\\g3\\G3 Version 4.0\\G3\\G3\\obj\\Release\\Intel Core.pdb"
		$PDB2 = "F:\\Projects\\g3\\G3 Version "
       		$PDB3 = "\\G3\\G3\\obj\\Release\\"
	condition:
		any of them
}