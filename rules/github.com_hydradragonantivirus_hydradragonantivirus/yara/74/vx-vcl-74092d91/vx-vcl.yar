import "pe"
rule _Vx_VCL_
{
	meta:
		description = "Vx: VCL"
	strings:
		$0 = {AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89}
	condition:
		$0 at pe.entry_point
}