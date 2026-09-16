import "pe"
rule _DIET_v100_v100d_
{
	meta:
		description = "DIET v1.00, v1.00d"
	strings:
		$0 = {BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC}
	condition:
		$0 at pe.entry_point
}