rule _aPack_v098b__Jibz_
{
	meta:
		description = "aPack v0.98b -> Jibz"
	strings:
		$0 = {93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA}
	condition:
		$0
}