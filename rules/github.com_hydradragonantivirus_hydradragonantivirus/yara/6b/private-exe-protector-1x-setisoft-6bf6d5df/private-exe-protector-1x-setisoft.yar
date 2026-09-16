import "pe"
rule _Private_Exe_Protector_1x__setisoft_
{
	meta:
		description = "Private Exe Protector 1.x -> setisoft"
	strings:
		$0 = {B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3}
	condition:
		$0 at pe.entry_point
}