import "pe"
rule _Microsoft_Cpp_19901992_
{
	meta:
		description = "Microsoft C++ (1990/1992)"
	strings:
		$0 = {B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB}
	condition:
		$0 at pe.entry_point
}