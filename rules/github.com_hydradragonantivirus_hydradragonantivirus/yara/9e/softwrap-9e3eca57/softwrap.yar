import "pe"
rule _SoftWrap_
{
	meta:
		description = "SoftWrap"
	strings:
		$0 = {9C 60 8B 44 24 24 E8 5D 81 ED 50 E8 ED 02 8C C0 0F}
	condition:
		$0 at pe.entry_point
}