import "pe"
rule _Anskya_Binder_v11__Anskya_
{
	meta:
		description = "Anskya Binder v1.1 -> Anskya"
	strings:
		$0 = {BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11}
	condition:
		$0 at pe.entry_point
}