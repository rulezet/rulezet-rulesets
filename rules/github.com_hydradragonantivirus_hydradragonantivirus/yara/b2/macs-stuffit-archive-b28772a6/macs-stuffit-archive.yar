import "pe"
rule _Macs_StuffIt_Archive_
{
	meta:
		description = "Mac`s StuffIt Archive"
	strings:
		$0 = {53 49 54 21 00}
	condition:
		$0 at pe.entry_point
}