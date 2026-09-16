import "pe"
rule _LEExe_Executable_Image_
{
	meta:
		description = "LE-Exe Executable Image"
	strings:
		$0 = {4C 45}
	condition:
		$0 at pe.entry_point
}