rule aspack_212
{
	meta:
		author = "PEiD"
		description = "ASPack 2.12 -> Alexey Solodovnikov"
		group = "100"
		function = "6"
	strings:
		$a0 = { 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 01 ?? ?? ?? EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$a0
}