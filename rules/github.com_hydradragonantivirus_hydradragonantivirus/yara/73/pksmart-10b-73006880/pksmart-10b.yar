import "pe"
rule _Pksmart_10b_
{
	meta:
		description = "Pksmart 1.0b"
	strings:
		$0 = {BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3}
	condition:
		$0 at pe.entry_point
}