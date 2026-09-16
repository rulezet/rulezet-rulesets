import "pe"
rule _PECompact_20betastudent_version__Jeremy_Collake_
{
	meta:
		description = "PECompact 2.0beta/student version -> Jeremy Collake"
	strings:
		$0 = {B8 ?? ?? ?? EE 05 12 13 13 12 50 64 FF 35 00 00 00 00 64 89 25 00}
	condition:
		$0 at pe.entry_point
}