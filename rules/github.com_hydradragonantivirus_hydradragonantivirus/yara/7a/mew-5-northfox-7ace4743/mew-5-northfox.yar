import "pe"
rule _MEW_5__Northfox_
{
	meta:
		description = "MEW 5 - Northfox"
	strings:
		$0 = {BE ?? ?? ?? ?? AD 91 AD 93 53 AD 96 56 5F AC}
	condition:
		$0 at pe.entry_point
}