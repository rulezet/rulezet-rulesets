import "pe"
rule _CreateInstall_Stub_v2003xx__Gentee_
{
	meta:
		description = "CreateInstall Stub v2003.x.x -> Gentee"
	strings:
		$0 = {81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80}
	condition:
		$0 at pe.entry_point
}