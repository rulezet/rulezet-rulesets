import "pe"
rule _EXE_Manager_Version_30_1994_c_Solar_Designer_
{
	meta:
		description = "EXE Manager Version 3.0 1994 (c) Solar Designer"
	strings:
		$0 = {B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2}
	condition:
		$0 at pe.entry_point
}