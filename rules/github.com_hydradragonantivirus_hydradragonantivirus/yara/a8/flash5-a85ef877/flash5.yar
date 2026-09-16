import "pe"
rule flash5
{
	meta:
		author = "PEiD"
		description = "Flash Projector/Player 5.0 -> Macromedia Inc."
		group = "22"
		function = "0"
	strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 }
	condition:
		$a0 at pe.entry_point
}