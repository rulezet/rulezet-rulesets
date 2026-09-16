import "pe"
rule _UPXShit_006_
{
	meta:
		description = "UPXShit 0.06"
	strings:
		$0 = {8C E0 0B C5 8C E0 0B C4 03 C5 74 ?? 74 ?? 8B}
	condition:
		$0 at pe.entry_point
}