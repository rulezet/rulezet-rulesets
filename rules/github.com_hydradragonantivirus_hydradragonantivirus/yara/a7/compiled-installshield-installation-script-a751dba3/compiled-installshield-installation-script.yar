import "pe"
rule _Compiled_InstallSHIELD_Installation_Script_
{
	meta:
		description = "Compiled InstallSHIELD Installation Script"
	strings:
		$0 = {B8 C9 0C 00}
	condition:
		$0 at pe.entry_point
}