import "pe"
rule _Vx_KBDflags1024_
{
	meta:
		description = "Vx: KBDflags.1024"
	strings:
		$0 = {8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22}
	condition:
		$0 at pe.entry_point
}