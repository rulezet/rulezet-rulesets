import "pe"
rule fsg131
{
	meta:
		author = "PEiD"
		description = "FSG 1.31 -> dulek/xt"
		group = "123"
		function = "0"
	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 }
	condition:
		$a0 at pe.entry_point
}