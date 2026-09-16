import "pe"
rule upx_hit001
{
	meta:
		author = "PEiD"
		description = "UPX$HiT 0.0.1 -> dj-siba"
		group = "158"
		function = "0"
	strings:
		$a0 = { 94 BC ?? ?? ?? ?? B9 ?? ?? ?? ?? 80 34 0C ?? E2 FA 94 }
	condition:
		$a0 at pe.entry_point
}