import "pe"
rule _Pelock_10x_
{
	meta:
		description = "Pelock 1.0x"
	strings:
		$0 = {4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45}
	condition:
		$0 at pe.entry_point
}