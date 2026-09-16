import "pe"
rule _UPXFreak_V01__HMX0101_
{
	meta:
		description = "UPXFreak V0.1 -> HMX0101"
	strings:
		$0 = {BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00}
	condition:
		$0 at pe.entry_point
}