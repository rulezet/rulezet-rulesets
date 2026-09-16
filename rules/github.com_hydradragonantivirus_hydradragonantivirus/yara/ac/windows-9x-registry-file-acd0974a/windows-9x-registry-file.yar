import "pe"
rule _Windows_9x_registry_file_
{
	meta:
		description = "Windows 9x registry file"
	strings:
		$0 = {43 52 45 47}
	condition:
		$0 at pe.entry_point
}