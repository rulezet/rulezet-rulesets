import "pe"
rule _KGCrypt_vxx_
{
	meta:
		description = "KGCrypt vx.x"
	strings:
		$0 = {60 66 9C BB 80 B3 ?? 10 40 ?? 90 4B 83 FB FF 75 F3 66 9D}
	condition:
		$0 at pe.entry_point
}