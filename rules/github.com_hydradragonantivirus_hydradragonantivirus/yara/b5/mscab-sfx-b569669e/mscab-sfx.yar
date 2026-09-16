rule mscab_sfx
{
	meta:
		author = "PEiD"
		description = "Microsoft CAB SFX module"
		group = "29"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 ?? 01 8B F0 8A 06 3C 22 75 }
	condition:
		$a0
}