import "pe"
rule _VcasmProtector_10e__vcasm_
{
	meta:
		description = "Vcasm-Protector 1.0e -> vcasm"
	strings:
		$0 = {EB 0A 5B 56 50 72 6F 74 65 63 74 5D}
	condition:
		$0 at pe.entry_point
}