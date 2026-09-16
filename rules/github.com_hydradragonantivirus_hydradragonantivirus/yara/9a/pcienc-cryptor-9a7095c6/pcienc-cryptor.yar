import "pe"
rule _PCIENC_Cryptor_
{
	meta:
		description = "PCIENC Cryptor"
	strings:
		$0 = {06 50 43 49 45 4E}
	condition:
		$0 at pe.entry_point
}