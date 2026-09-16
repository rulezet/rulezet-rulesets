import "pe"
rule _FSG_v133a__dulekxt_
{
	meta:
		description = "FSG v1.33a -> dulek/xt"
	strings:
		$0 = {BE A8 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73}
	condition:
		$0 at pe.entry_point
}