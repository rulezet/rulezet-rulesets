import "pe"
rule _COM2EXE_
{
	meta:
		description = "COM2EXE"
	strings:
		$0 = {F0 FF FE FF}
	condition:
		$0 at pe.entry_point
}