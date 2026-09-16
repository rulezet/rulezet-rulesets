import "pe"
rule _BGI_Device_Driver_
{
	meta:
		description = "BGI Device Driver"
	strings:
		$0 = {70 6B 08 08 42 47 49 20}
	condition:
		$0 at pe.entry_point
}