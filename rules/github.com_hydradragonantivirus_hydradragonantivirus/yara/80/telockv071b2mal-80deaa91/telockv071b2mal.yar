import "pe"
rule tElockv071b2mal
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 44 11 00 00 C3 83 }

condition:
		$a0 at pe.entry_point
}