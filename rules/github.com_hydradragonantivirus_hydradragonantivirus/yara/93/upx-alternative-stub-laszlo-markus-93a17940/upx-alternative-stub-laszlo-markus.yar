import "pe"
rule _UPX_Alternative_stub__Laszlo__Markus_
{
	meta:
		description = "UPX Alternative stub -> Laszlo & Markus"
	strings:
		$0 = {EB 02 EB EA EB FC 8A 06}
	condition:
		$0 at pe.entry_point
}