import "pe"
rule _Unpacked_BSSFX_Archive_v19_
{
	meta:
		description = "Unpacked BS-SFX Archive v1.9"
	strings:
		$0 = {1E 33 C0 50 B8 ?? ?? 8E D8 FA 8E D0 BC ?? ?? FB B8 ?? ?? CD 21 3C 03 73}
	condition:
		$0 at pe.entry_point
}