import "pe"
rule _PKLITE_v150_Device_driver_compression_
{
	meta:
		description = "PKLITE v1.50 (Device driver compression)"
	strings:
		$0 = {B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB}
	condition:
		$0 at pe.entry_point
}