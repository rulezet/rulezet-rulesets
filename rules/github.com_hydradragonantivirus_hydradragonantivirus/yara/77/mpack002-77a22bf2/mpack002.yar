import "pe"
rule mPack002 : Delta Aziz
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 4E ?? ?? 00 00 00 00 00 00 00 00 00 5E ?? ?? 00 4E ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6C ?? ?? 00 7D ?? ?? 00 90 ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 ?? ?? 00 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 }
	condition:
		$a0 at pe.entry_point and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00009E00)
}