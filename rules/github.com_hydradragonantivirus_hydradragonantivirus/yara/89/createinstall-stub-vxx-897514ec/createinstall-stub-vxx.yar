import "pe"
rule _CreateInstall_Stub_vxx_
{
	meta:
		description = "CreateInstall Stub vx.x"
	strings:
		$0 = {55 E8 5D 83 ED 06 8B C5 55 60 89 AD 2B}
	condition:
		$0 at pe.entry_point
}