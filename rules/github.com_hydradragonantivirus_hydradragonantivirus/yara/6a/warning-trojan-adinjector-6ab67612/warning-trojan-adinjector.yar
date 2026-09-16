import "pe"
rule _WARNING__TROJAN__ADinjector_
{
	meta:
		description = "WARNING -> TROJAN -> ADinjector"
	strings:
		$0 = {90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E}
	condition:
		$0 at pe.entry_point
}