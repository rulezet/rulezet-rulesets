import "pe"
rule _Zurenava_DOS_Extender_v045_v049_
{
	meta:
		description = "Zurenava DOS Extender v0.45, v0.49"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? 56 FC F3 A5 5F E9}
	condition:
		$0 at pe.entry_point
}