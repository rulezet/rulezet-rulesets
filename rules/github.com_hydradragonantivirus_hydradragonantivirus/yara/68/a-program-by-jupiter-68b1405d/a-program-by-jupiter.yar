import "pe"
rule _A_program_by_Jupiter__
{
	meta:
		description = "A program by Jupiter .."
	strings:
		$0 = {2B C0 74 05 68 ?? ?? ?? ?? 50}
	condition:
		$0 at pe.entry_point
}