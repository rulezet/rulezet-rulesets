import "pe"
rule _EP_ExE_Pack_V10__Elite_Coding_Group_
{
	meta:
		description = "!EP (ExE Pack) V1.0 -> Elite Coding Group"
	strings:
		$0 = {60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10}
	condition:
		$0 at pe.entry_point
}