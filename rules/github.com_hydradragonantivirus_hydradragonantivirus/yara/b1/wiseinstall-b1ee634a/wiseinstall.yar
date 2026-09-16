import "pe"
rule wiseinstall
{
	meta:
		author = "PEiD"
		description = "Wise Installer stub"
		group = "306"
		function = "0"
	strings:
		$a0 = { 53 54 55 42 33 32 2E 45 58 45 ?? 5F 4D 61 69 6E 57 6E 64 50 72 6F 63 40 31 36 ?? 5F 53 }
	condition:
		$a0 at pe.entry_point
}