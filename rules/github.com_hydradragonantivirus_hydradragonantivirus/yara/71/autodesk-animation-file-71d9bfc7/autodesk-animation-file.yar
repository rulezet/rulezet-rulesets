import "pe"
rule _AutoDesk_Animation_file_
{
	meta:
		description = "AutoDesk Animation file"
	strings:
		$0 = {00 12 AF ?? ?? 40 01 C8}
	condition:
		$0 at pe.entry_point
}