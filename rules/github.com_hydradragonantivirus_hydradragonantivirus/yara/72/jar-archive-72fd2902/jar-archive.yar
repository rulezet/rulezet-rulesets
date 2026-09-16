import "pe"
rule _JAR_Archive_
{
	meta:
		description = "JAR Archive"
	strings:
		$0 = {1A 4A 61 72 1B}
	condition:
		$0 at pe.entry_point
}