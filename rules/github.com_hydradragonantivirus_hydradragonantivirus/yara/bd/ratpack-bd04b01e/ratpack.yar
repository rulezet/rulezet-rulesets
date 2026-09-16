import "pe"
rule ratpack
{
	meta:
		author = "PEiD"
		description = "RatPacker (glue) stub"
		group = "308"
		function = "0"
	strings:
		$a0 = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }
	condition:
		$a0 at pe.entry_point
}