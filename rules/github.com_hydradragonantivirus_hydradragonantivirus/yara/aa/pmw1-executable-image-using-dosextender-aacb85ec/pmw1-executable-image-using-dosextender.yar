import "pe"
rule _PMW1_Executable_Image_using_DOSExtender_
{
	meta:
		description = "PMW1 Executable Image (using DOSExtender)"
	strings:
		$0 = {50 4D 57 31}
	condition:
		$0 at pe.entry_point
}