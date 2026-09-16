import "pe"
rule _EmbedPE_v124__cyclotron_
{
	meta:
		description = "EmbedPE v1.24 -> cyclotron"
	strings:
		$0 = {83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00}
	condition:
		$0 at pe.entry_point
}