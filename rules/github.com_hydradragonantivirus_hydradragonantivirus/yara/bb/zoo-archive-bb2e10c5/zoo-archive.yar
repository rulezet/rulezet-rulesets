import "pe"
rule _ZOO_Archive_
{
	meta:
		description = "ZOO Archive"
	strings:
		$0 = {5A 4F 4F}
	condition:
		$0 at pe.entry_point
}