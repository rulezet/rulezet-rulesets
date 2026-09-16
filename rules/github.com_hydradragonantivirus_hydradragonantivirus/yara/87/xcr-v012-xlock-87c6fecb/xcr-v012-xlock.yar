import "pe"
rule _XCR_v012__XLock_
{
	meta:
		description = "XCR v0.12 -> X-Lock"
	strings:
		$0 = {60 9C E8 00 00 00 00 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D}
	condition:
		$0 at pe.entry_point
}