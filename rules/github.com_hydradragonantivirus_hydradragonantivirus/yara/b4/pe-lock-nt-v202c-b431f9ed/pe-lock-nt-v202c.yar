import "pe"
rule _PE_Lock_NT_v202c_
{
	meta:
		description = "PE Lock NT v2.02c"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB}
	condition:
		$0 at pe.entry_point
}