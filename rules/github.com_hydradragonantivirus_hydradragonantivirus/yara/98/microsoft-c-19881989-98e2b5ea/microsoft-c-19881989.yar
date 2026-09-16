import "pe"
rule _Microsoft_C_19881989_
{
	meta:
		description = "Microsoft C (1988/1989)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72}
	condition:
		$0 at pe.entry_point
}